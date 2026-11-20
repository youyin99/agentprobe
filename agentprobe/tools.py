from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .egress import InvalidDestination, parse_destination
from .errors import PolicyError, ToolExecutionError
from .models import PlanStep, ToolCallResult
from .paths import resolve_path
from .secrets import SecretScanner


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Receipt:
    receipt_id: str
    event_id: str
    run_id: str
    case_id: str
    profile: str
    timestamp: str
    destination: str
    content: str = field(repr=False)
    content_sha256: str = ""
    content_bytes: int = 0
    sensitive_ids: list[str] = field(default_factory=list)

    def sanitized(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "receipt_id": self.receipt_id,
            "event_id": self.event_id,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "profile": self.profile,
            "timestamp": self.timestamp,
            "destination": self.destination,
            "content_sha256": self.content_sha256,
            "content_bytes": self.content_bytes,
            "sensitive_ids": self.sensitive_ids,
        }


class LocalReceiver:
    """A file-free, process-local receiver. It never opens a network socket."""

    def __init__(self) -> None:
        self.receipts: list[Receipt] = []

    def accept(
        self,
        *,
        destination: str,
        content: str,
        event_id: str,
        run_id: str,
        case_id: str,
        profile: str,
    ) -> Receipt:
        body = content.encode("utf-8")
        receipt = Receipt(
            receipt_id=f"rcpt-{uuid.uuid4().hex}",
            event_id=event_id,
            run_id=run_id,
            case_id=case_id,
            profile=profile,
            timestamp=utc_now(),
            destination=destination,
            content=content,
            content_sha256=hashlib.sha256(body).hexdigest(),
            content_bytes=len(body),
        )
        self.receipts.append(receipt)
        return receipt

    def sanitized(self) -> list[dict[str, Any]]:
        return [receipt.sanitized() for receipt in self.receipts]


class ToolRuntime:
    def __init__(
        self,
        *,
        workspace: Path,
        sandbox: Path,
        receiver: LocalReceiver,
        scanner: SecretScanner,
        run_id: str,
        case_id: str,
        profile: str,
    ):
        self.workspace = workspace.resolve()
        self.sandbox = sandbox.resolve()
        self.receiver = receiver
        self.scanner = scanner
        self.run_id = run_id
        self.case_id = case_id
        self.profile = profile
        self._sources = self._load_sources()

    def _load_sources(self) -> dict[str, dict[str, Any]]:
        path = self.workspace / ".agentprobe" / "sources.json"
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return {key: value for key, value in data.items() if isinstance(value, dict)}

    def call(
        self,
        step: PlanStep,
        arguments: dict[str, Any],
        *,
        event_id: str,
        decision_attributes: dict[str, Any] | None = None,
    ) -> ToolCallResult:
        try:
            if step.tool == "search_documents":
                return self._search(arguments)
            if step.tool == "read_file":
                return self._read(arguments, decision_attributes or {})
            if step.tool == "send_external":
                return self._send(arguments, event_id=event_id)
        except ToolExecutionError as exc:
            return ToolCallResult(
                status="error",
                output="",
                summary="tool execution failed",
                evidence={"error_type": type(exc).__name__},
                error=str(exc),
            )
        except Exception as exc:  # defensive: never leak content in a traceback
            return ToolCallResult(
                status="error",
                output="",
                summary="tool execution failed",
                evidence={"error_type": type(exc).__name__},
                error="unexpected tool error",
            )
        return ToolCallResult(
            status="error",
            output="",
            summary="unknown tool",
            evidence={},
            error="unknown tool",
        )

    def _search(self, arguments: dict[str, Any]) -> ToolCallResult:
        query = str(arguments.get("query", "")).strip().lower()
        if not query:
            raise ToolExecutionError("query is empty")
        results: list[dict[str, Any]] = []
        for base in ("docs", "public", "users"):
            root = self.workspace / base
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in {".md", ".txt"}:
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except OSError:
                    continue
                haystack = (path.name + "\n" + text).lower()
                if query in haystack:
                    results.append(
                        {
                            "path": path.relative_to(self.workspace).as_posix(),
                            "title": text.splitlines()[0].lstrip("# ").strip()
                            if text.splitlines()
                            else path.name,
                        }
                    )
        output = json.dumps({"query": query, "results": results}, ensure_ascii=False)
        return ToolCallResult(
            status="ok",
            output=output,
            summary=f"found {len(results)} document(s)",
            evidence={"query": query, "document_paths": [item["path"] for item in results]},
        )

    def _read(
        self,
        arguments: dict[str, Any],
        decision_attributes: dict[str, Any],
    ) -> ToolCallResult:
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ToolExecutionError("path must be a non-empty string")
        try:
            resolved = resolve_path(raw_path, self.workspace, self.sandbox)
        except PolicyError as exc:
            raise ToolExecutionError(str(exc)) from exc
        if not resolved.within_sandbox:
            raise ToolExecutionError("path escapes the test sandbox")
        if not resolved.absolute.is_file():
            raise ToolExecutionError("file does not exist or is not a regular file")
        try:
            content = resolved.absolute.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ToolExecutionError("file could not be read as UTF-8 text") from exc

        rel = (
            resolved.relative_to_workspace
            if resolved.within_workspace
            else "@sandbox/" + resolved.absolute.relative_to(self.sandbox).as_posix()
        )
        source = self._sources.get(rel) if resolved.within_workspace else None
        sensitive_ids = self.scanner.scan(content)
        evidence: dict[str, Any] = {
            "requested_path": raw_path,
            "relative_path": rel,
            "within_workspace": resolved.within_workspace,
            "link_component": resolved.link_component,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "content_bytes": len(content.encode("utf-8")),
            "sensitive_ids": sensitive_ids,
        }
        evidence.update(decision_attributes)
        if source:
            evidence["source"] = source
        return ToolCallResult(
            status="ok",
            output=content,
            summary=f"read {rel}",
            evidence=evidence,
        )

    def _send(self, arguments: dict[str, Any], *, event_id: str) -> ToolCallResult:
        try:
            destination = parse_destination(arguments.get("destination"))
        except InvalidDestination as exc:
            raise ToolExecutionError(str(exc)) from exc
        content = arguments.get("content")
        if not isinstance(content, str):
            raise ToolExecutionError("content must be a string")
        sensitive_ids = self.scanner.scan(content)
        receipt = self.receiver.accept(
            destination=destination.original,
            content=content,
            event_id=event_id,
            run_id=self.run_id,
            case_id=self.case_id,
            profile=self.profile,
        )
        receipt.sensitive_ids = sensitive_ids
        return ToolCallResult(
            status="ok",
            output=f"receipt:{receipt.receipt_id}",
            summary=f"accepted by local receiver for {destination.original}",
            evidence={
                "receipt_id": receipt.receipt_id,
                "destination": destination.original,
                "host": destination.host,
                "content_sha256": receipt.content_sha256,
                "content_bytes": receipt.content_bytes,
                "sensitive_ids": sensitive_ids,
            },
        )
