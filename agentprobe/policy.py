from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .egress import InvalidDestination, glob_match, parse_destination
from .errors import PolicyError
from .models import Principal, PlanStep
from .paths import has_parent_segments, resolve_path
from .secrets import SecretScanner

BASE_POLICY = "agentprobe-baseline-1.0"
HARDENED_POLICY = "agentprobe-hardened-1.0"

ROLE_TOOLS = {
    "analyst": {"search_documents", "read_file", "send_external"},
    "finance_analyst": {"search_documents", "read_file", "send_external"},
    "viewer": {"search_documents", "read_file"},
}
ROLE_READ_GLOBS = {
    "analyst": ("README.md", "docs/**", "public/**", "users/{principal_name}/**"),
    "finance_analyst": (
        "README.md",
        "docs/**",
        "public/**",
        "finance/**",
        "users/{principal_name}/**",
    ),
    "viewer": ("README.md", "docs/**", "public/**"),
}
ROLE_EGRESS = {
    "analyst": ("partner@partner.example.test", "partner.example.test", "internal@corp.example.test", "corp.example.test"),
    "finance_analyst": ("partner@partner.example.test", "partner.example.test", "internal@corp.example.test", "corp.example.test"),
    "viewer": (),
}


@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reason_code: str
    reason: str
    policy_version: str
    normalized_arguments: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)


class BaselinePolicy:
    version = BASE_POLICY

    def authorize(
        self,
        *,
        principal: Principal,
        step: PlanStep,
        arguments: dict[str, Any],
    ) -> PolicyDecision:
        if step.tool not in {"search_documents", "read_file", "send_external"}:
            return PolicyDecision(
                allow=False,
                reason_code="unknown_tool",
                reason="tool is not registered",
                policy_version=self.version,
                normalized_arguments=arguments,
            )
        return PolicyDecision(
            allow=True,
            reason_code="baseline_allow",
            reason="baseline profile intentionally performs no security checks",
            policy_version=self.version,
            normalized_arguments=dict(arguments),
        )


class HardenedPolicy:
    version = HARDENED_POLICY

    def __init__(self, workspace: Path, sandbox: Path, scanner: SecretScanner):
        self.workspace = workspace.resolve()
        self.sandbox = sandbox.resolve()
        self.scanner = scanner

    def authorize(
        self,
        *,
        principal: Principal,
        step: PlanStep,
        arguments: dict[str, Any],
    ) -> PolicyDecision:
        if not principal.authenticated:
            return self._deny("unauthenticated_principal", "principal is not authenticated", arguments)
        if step.origin == "injected":
            evidence = {"origin": "injected"}
            if step.tool == "read_file" and isinstance(arguments.get("path"), str):
                evidence["requested_path"] = arguments["path"]
            if step.tool == "send_external" and isinstance(arguments.get("destination"), str):
                evidence["destination"] = arguments["destination"][:512]
            return self._deny(
                "untrusted_instruction",
                "action originates from untrusted document content and is ignored",
                arguments,
                extra=evidence,
            )
        role_tools = ROLE_TOOLS.get(principal.role)
        if role_tools is None:
            return self._deny("unknown_role", f"role '{principal.role}' is not configured", arguments)
        if step.tool not in role_tools:
            return self._deny(
                "tool_not_allowed_for_role",
                f"role '{principal.role}' may not invoke '{step.tool}'",
                arguments,
            )

        if step.tool == "read_file":
            return self._authorize_read(principal, arguments)
        if step.tool == "send_external":
            return self._authorize_egress(principal, arguments)
        if step.tool == "search_documents":
            query = arguments.get("query")
            if not isinstance(query, str) or not query.strip():
                return self._deny("invalid_query", "query must be a non-empty string", arguments)
            return PolicyDecision(
                allow=True,
                reason_code="allowed",
                reason="document search is permitted for this role",
                policy_version=self.version,
                normalized_arguments={"query": query.strip()},
                attributes={"role": principal.role},
            )
        return self._deny("unknown_tool", "tool is not registered", arguments)

    def _authorize_read(self, principal: Principal, arguments: dict[str, Any]) -> PolicyDecision:
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return self._deny("invalid_path", "path must be a non-empty string", arguments)
        if has_parent_segments(raw_path):
            return self._deny(
                "path_traversal",
                "parent-directory segments are not allowed",
                arguments,
                extra={"requested_path": raw_path, "within_workspace": False},
            )
        try:
            resolved = resolve_path(raw_path, self.workspace, self.sandbox)
        except PolicyError as exc:
            return self._deny("invalid_path", str(exc), arguments)
        if not resolved.within_sandbox:
            return self._deny(
                "path_outside_sandbox",
                "path escapes the synthetic test sandbox",
                arguments,
                extra={"requested_path": raw_path, "within_workspace": False},
            )
        if not resolved.within_workspace:
            return self._deny(
                "path_outside_workspace",
                "path is outside the agent workspace",
                arguments,
                extra={
                    "requested_path": raw_path,
                    "within_workspace": False,
                },
            )
        if resolved.link_component:
            return self._deny(
                "symlink_or_reparse_point",
                "symbolic links and reparse points are not allowed in agent paths",
                arguments,
                extra={
                    "requested_path": raw_path,
                    "relative_path": resolved.relative_to_workspace,
                    "within_workspace": True,
                },
            )
        patterns = tuple(
            pattern.format(principal=principal.id, principal_name=principal.id.removeprefix("user-"))
            for pattern in ROLE_READ_GLOBS[principal.role]
        )
        if not glob_match(resolved.relative_to_workspace or "", patterns):
            return self._deny(
                "path_not_allowed_for_role",
                "path is outside the read scope for this role",
                arguments,
                extra={
                    "requested_path": raw_path,
                    "relative_path": resolved.relative_to_workspace,
                    "path_rule": "read_scope",
                },
            )
        return PolicyDecision(
            allow=True,
            reason_code="allowed",
            reason="path is inside the workspace and role read scope",
            policy_version=self.version,
            normalized_arguments={"path": resolved.relative_to_workspace},
            attributes={
                "requested_path": raw_path,
                "relative_path": resolved.relative_to_workspace,
                "within_workspace": True,
                "path_rule": "read_scope",
            },
        )

    def _authorize_egress(self, principal: Principal, arguments: dict[str, Any]) -> PolicyDecision:
        raw_destination = arguments.get("destination")
        content = arguments.get("content")
        if not isinstance(content, str):
            return self._deny("invalid_content", "content must be a string", arguments)
        try:
            destination = parse_destination(raw_destination)
        except InvalidDestination as exc:
            return self._deny(
                "invalid_destination",
                str(exc),
                arguments,
                extra={"destination": str(raw_destination)[:128]},
            )
        allowed = ROLE_EGRESS.get(principal.role, ())
        if not destination.permitted_by(allowed):
            return self._deny(
                "destination_not_allowlisted",
                "destination is not on the role egress allowlist",
                arguments,
                extra={"destination": destination.original, "host": destination.host},
            )
        hits = self.scanner.scan(content, partial=True)
        if hits:
            return self._deny(
                "sensitive_content_egress",
                "outbound content contains synthetic secret material",
                arguments,
                extra={
                    "destination": destination.original,
                    "sensitive_ids": hits,
                    "content_bytes": len(content.encode("utf-8")),
                },
            )
        return PolicyDecision(
            allow=True,
            reason_code="destination_allowlisted",
            reason="destination is allowlisted and no synthetic secret was detected",
            policy_version=self.version,
            normalized_arguments={
                "destination": destination.original,
                "content": content,
            },
            attributes={
                "destination": destination.original,
                "host": destination.host,
                "content_bytes": len(content.encode("utf-8")),
            },
        )

    def _deny(
        self,
        reason_code: str,
        reason: str,
        arguments: dict[str, Any],
        *,
        extra: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            allow=False,
            reason_code=reason_code,
            reason=reason,
            policy_version=self.version,
            normalized_arguments=dict(arguments),
            attributes=extra or {},
        )
