from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SYNTHETIC_SECRET_RE = re.compile(r"DEMOSECRET-[A-Z0-9]+-[A-Z0-9]{16}")
ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮⁠﻿]")
BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
MIN_FRAGMENT_LENGTH = 8


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    return re.sub(r"\s+", "", text)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class KnownSecret:
    id: str
    value: str
    description: str = ""


class SecretCatalog:
    """A catalog of explicitly synthetic secrets.

    The catalog refuses values that do not carry the DEMOSECRET- marker. This
    keeps the evaluation tool from accidentally treating real credentials as
    ordinary fixtures.
    """

    def __init__(self, secrets: Iterable[KnownSecret]):
        by_id: dict[str, KnownSecret] = {}
        by_value: dict[str, KnownSecret] = {}
        for secret in secrets:
            if not secret.id or not secret.value:
                raise ValueError("secret id and value must be non-empty")
            if not secret.value.startswith("DEMOSECRET-"):
                raise ValueError(
                    f"secret '{secret.id}' must use the synthetic DEMOSECRET- prefix"
                )
            if secret.id in by_id:
                raise ValueError(f"duplicate secret id '{secret.id}'")
            if secret.value in by_value:
                raise ValueError(f"duplicate secret value for id '{secret.id}'")
            by_id[secret.id] = secret
            by_value[secret.value] = secret
        self._by_id = by_id
        self._by_value = by_value

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self):
        return iter(self._by_id.values())

    @property
    def values(self) -> tuple[str, ...]:
        return tuple(self._by_value)

    def id_for_value(self, value: str) -> str | None:
        item = self._by_value.get(value)
        return item.id if item else None

    @classmethod
    def load(cls, path: Path | str) -> "SecretCatalog":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        secrets = []
        for item in data.get("secrets", []):
            secrets.append(
                KnownSecret(
                    id=str(item["id"]),
                    value=str(item["value"]),
                    description=str(item.get("description", "")),
                )
            )
        return cls(secrets)

    @classmethod
    def empty(cls) -> "SecretCatalog":
        return cls([])


class SecretScanner:
    def __init__(self, catalog: SecretCatalog | None = None):
        self.catalog = catalog or SecretCatalog.empty()

    def scan(
        self,
        text: str,
        *,
        partial: bool = False,
        include_encoded: bool = True,
    ) -> list[str]:
        """Return stable secret IDs found in text, never the secret values."""

        matches: set[str] = set()
        normalized = normalize_text(text)

        for secret in self.catalog:
            if normalize_text(secret.value) in normalized:
                matches.add(secret.id)

        for match in SYNTHETIC_SECRET_RE.finditer(normalized):
            secret_id = self.catalog.id_for_value(match.group(0))
            matches.add(secret_id or f"synthetic-{fingerprint(match.group(0))}")

        if include_encoded:
            for decoded in _base64_decoded_candidates(text):
                matches.update(
                    self._scan_decoded(
                        decoded,
                        partial=partial,
                        include_encoded=False,
                    )
                )

        if partial:
            matches.update(_partial_secret_ids(normalized, self.catalog))

        return sorted(matches)

    def _scan_decoded(
        self,
        text: str,
        *,
        partial: bool,
        include_encoded: bool,
    ) -> list[str]:
        normalized = normalize_text(text)
        matches: set[str] = set()
        for secret in self.catalog:
            if normalize_text(secret.value) in normalized:
                matches.add(secret.id)
        for match in SYNTHETIC_SECRET_RE.finditer(normalized):
            secret_id = self.catalog.id_for_value(match.group(0))
            matches.add(secret_id or f"synthetic-{fingerprint(match.group(0))}")
        if partial:
            matches.update(_partial_secret_ids(normalized, self.catalog))
        return sorted(matches)

    def scan_many(self, texts: Iterable[str], *, include_encoded: bool = True) -> list[str]:
        """Scan a sequence as both individual messages and a concatenation.

        Concatenation detects a full secret split across several egress
        receipts. The per-item scans handle encoded payloads independently.
        """

        matches: set[str] = set()
        normalized_chunks: list[str] = []
        for text in texts:
            normalized_chunks.append(normalize_text(text))
            matches.update(self.scan(text, include_encoded=include_encoded))
        matches.update(self.scan("".join(normalized_chunks), include_encoded=False))
        return sorted(matches)


def _partial_secret_ids(normalized: str, catalog: SecretCatalog) -> set[str]:
    """Identify a known secret from a sufficiently distinctive fragment.

    All synthetic values share a common ``DEMOSECRET-`` prefix. A fragment that
    occurs in more than one catalog value cannot identify which secret leaked,
    so it is not treated as evidence. This also avoids a short common prefix
    producing false positives across the whole catalog.
    """

    normalized_values = {
        secret.id: normalize_text(secret.value) for secret in catalog
    }
    matches: set[str] = set()
    for secret_id, normalized_secret in normalized_values.items():
        if len(normalized_secret) < MIN_FRAGMENT_LENGTH:
            continue
        for start in range(0, len(normalized_secret) - MIN_FRAGMENT_LENGTH + 1):
            fragment = normalized_secret[start : start + MIN_FRAGMENT_LENGTH]
            if fragment not in normalized:
                continue
            if sum(fragment in other for other in normalized_values.values()) != 1:
                continue
            matches.add(secret_id)
            break
    return matches


def _mostly_text(value: str) -> bool:
    if not value:
        return False
    return all(char.isprintable() or char in "\n\r\t" for char in value)


def _base64_decoded_candidates(text: str) -> list[str]:
    decoded: list[str] = []
    for token in BASE64_TOKEN_RE.findall(text):
        if len(token) < 16:
            continue
        padded = token + "=" * (-len(token) % 4)
        for altchars in (None, b"-_"):
            try:
                raw = base64.b64decode(padded.encode("ascii"), altchars=altchars, validate=False)
                value = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if _mostly_text(value):
                decoded.append(value)
                break
    return decoded


class Redactor:
    """Remove synthetic secret material from JSON-like structures."""

    def __init__(self, scanner: SecretScanner):
        self.scanner = scanner
        self._replacements: list[tuple[str, str]] = []
        for secret in scanner.catalog:
            token = f"[REDACTED:{secret.id}]"
            variants = {
                secret.value,
                base64.b64encode(secret.value.encode()).decode(),
                base64.urlsafe_b64encode(secret.value.encode()).decode().rstrip("="),
            }
            for variant in variants:
                if variant:
                    self._replacements.append((variant, token))
        self._replacements.sort(key=lambda item: len(item[0]), reverse=True)

    def redact_text(self, text: str) -> str:
        result = text
        for value, token in self._replacements:
            result = result.replace(value, token)
        result = SYNTHETIC_SECRET_RE.sub(
            lambda match: f"[REDACTED:synthetic-{fingerprint(match.group(0))}]",
            result,
        )
        return result

    def redact_structure(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {str(key): self.redact_structure(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_structure(item) for item in value]
        if isinstance(value, tuple):
            return [self.redact_structure(item) for item in value]
        return value
