from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class InvalidDestination(ValueError):
    pass


@dataclass(frozen=True)
class Destination:
    original: str
    host: str
    scheme: str

    def permitted_by(self, patterns: tuple[str, ...] | list[str] | set[str]) -> bool:
        for pattern in patterns:
            pattern = pattern.lower().strip()
            if not pattern:
                continue
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if self.host.endswith(suffix) and self.host != suffix.lstrip("."):
                    return True
            elif pattern == self.original.lower() or pattern == self.host:
                return True
        return False


def parse_destination(raw: object) -> Destination:
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidDestination("destination must be a non-empty string")
    value = raw.strip()
    if any(ord(char) < 0x20 for char in value):
        raise InvalidDestination("destination contains control characters")
    if len(value) > 512:
        raise InvalidDestination("destination is too long")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https":
            raise InvalidDestination("only https URLs are allowed")
        if parsed.username or parsed.password:
            raise InvalidDestination("credentials in URLs are not allowed")
        host = (parsed.hostname or "").lower()
        if not host or not DOMAIN_RE.fullmatch(host):
            raise InvalidDestination("invalid destination host")
        return Destination(original=value.lower(), host=host, scheme="https")
    email_match = EMAIL_RE.fullmatch(value)
    if email_match:
        return Destination(
            original=value.lower(),
            host=email_match.group(1).lower(),
            scheme="email",
        )
    if DOMAIN_RE.fullmatch(value):
        return Destination(original=value.lower(), host=value.lower(), scheme="domain")
    raise InvalidDestination("destination must be an email address, domain, or https URL")


def glob_match(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    posix = path.replace("\\", "/").lstrip("./")
    return any(fnmatch.fnmatchcase(posix, pattern) for pattern in patterns)
