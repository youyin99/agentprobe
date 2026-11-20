from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import PlanStep, TestCase, ToolCallResult
from .policy import BaselinePolicy, HardenedPolicy, PolicyDecision
from .secrets import Redactor, SecretScanner
from .templating import TemplateError, render_arguments
from .tools import LocalReceiver, Receipt, ToolRuntime, utc_now


class MonotonicClock:
    def __init__(self) -> None:
        self._last: datetime | None = None

    def now(self) -> str:
        current = datetime.now(UTC)
        if self._last is not None and current <= self._last:
            current = self._last + timedelta(milliseconds=1)
        self._last = current
        return current.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class ActionOutcome:
    step_id: str
    tool: str
    origin: str
    purpose: str
    decision: str
    reason_code: str
    status: str
    event_id: str
    receipt_id: str | None = None
    sensitive_ids: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    case: TestCase
    profile: str
    run_id: str
    events: list[dict[str, Any]]
    receipts: list[Receipt]
    actions: list[ActionOutcome]
    errors: list[str]
    clock: MonotonicClock

    @property
    def successful_receipts(self) -> list[Receipt]:
        return list(self.receipts)

    def aggregate_sensitive_ids(self, scanner: SecretScanner) -> list[str]:
        return scanner.scan_many([receipt.content for receipt in self.receipts])

    def sanitized_receipts(self, scanner: SecretScanner) -> list[dict[str, Any]]:
        aggregate = self.aggregate_sensitive_ids(scanner)
        output = []
        for receipt in self.receipts:
            item = receipt.sanitized()
            item["run_sensitive_ids"] = aggregate
            output.append(item)
        return output


def _safe_arguments(tool: str, arguments: dict[str, Any], redactor: Redactor) -> dict[str, Any]:
    if tool == "send_external":
        content = arguments.get("content")
        body = content.encode("utf-8") if isinstance(content, str) else b""
        return {
            "destination": str(arguments.get("destination", ""))[:512],
            "content": f"<redacted:sha256:{hashlib.sha256(body).hexdigest()}>",
            "content_bytes": len(body),
        }
    return redactor.redact_structure(arguments)


class CaseRunner:
    def __init__(
        self,
        *,
        workspace: Path,
        sandbox: Path,
        scanner: SecretScanner,
        profile: str,
        clock: MonotonicClock | None = None,
    ):
        self.workspace = workspace.resolve()
        self.sandbox = sandbox.resolve()
        self.scanner = scanner
        self.profile = profile
        self.clock = clock or MonotonicClock()
        self.redactor = Redactor(scanner)
        if profile == "baseline":
            self.policy = BaselinePolicy()
        elif profile == "hardened":
            self.policy = HardenedPolicy(self.workspace, self.sandbox, scanner)
        else:
            raise ValueError(f"unknown profile '{profile}'")

    def run(self, case: TestCase) -> RunResult:
        run_id = f"run-{uuid.uuid4().hex}"
        receiver = LocalReceiver()
        runtime = ToolRuntime(
            workspace=self.workspace,
            sandbox=self.sandbox,
            receiver=receiver,
            scanner=self.scanner,
            run_id=run_id,
            case_id=case.id,
            profile=self.profile,
        )
        events: list[dict[str, Any]] = []
        actions: list[ActionOutcome] = []
        errors: list[str] = []
        step_outputs: dict[str, str] = {}
        step_event_ids: dict[str, str] = {}

        for sequence, step in enumerate(case.plan, start=1):
            event_id = f"evt-{uuid.uuid4().hex}"
            try:
                arguments, references = render_arguments(step.args, step_outputs)
            except TemplateError as exc:
                errors.append(f"{step.id}: template error")
                event = self._event(
                    case=case,
                    run_id=run_id,
                    event_id=event_id,
                    sequence=sequence,
                    step=step,
                    arguments=step.args,
                    decision=PolicyDecision(
                        allow=False,
                        reason_code="template_error",
                        reason=str(exc),
                        policy_version=getattr(self.policy, "version", "unknown"),
                    ),
                    parent=None,
                    status="error",
                    summary="action template could not be rendered",
                    evidence={"error_type": "template_error"},
                )
                events.append(event)
                actions.append(
                    ActionOutcome(
                        step_id=step.id,
                        tool=step.tool,
                        origin=step.origin,
                        purpose=step.purpose,
                        decision="deny",
                        reason_code="template_error",
                        status="error",
                        event_id=event_id,
                    )
                )
                step_outputs[step.id] = ""
                step_event_ids[step.id] = event_id
                continue

            parent = step_event_ids[references[0]] if references else None
            decision = self.policy.authorize(
                principal=case.principal,
                step=step,
                arguments=arguments,
            )

            if not decision.allow:
                event = self._event(
                    case=case,
                    run_id=run_id,
                    event_id=event_id,
                    sequence=sequence,
                    step=step,
                    arguments=arguments,
                    decision=decision,
                    parent=parent,
                    status="denied",
                    summary="blocked before tool execution",
                    evidence=dict(decision.attributes),
                )
                events.append(event)
                step_outputs[step.id] = ""
                step_event_ids[step.id] = event_id
                actions.append(
                    ActionOutcome(
                        step_id=step.id,
                        tool=step.tool,
                        origin=step.origin,
                        purpose=step.purpose,
                        decision="deny",
                        reason_code=decision.reason_code,
                        status="denied",
                        event_id=event_id,
                    )
                )
                continue

            result: ToolCallResult = runtime.call(
                step,
                dict(decision.normalized_arguments),
                event_id=event_id,
                decision_attributes=dict(decision.attributes),
            )
            if result.status == "error":
                errors.append(f"{step.id}: {result.error or 'tool error'}")
            receipt_id = None
            if isinstance(result.evidence, dict):
                receipt_id = result.evidence.get("receipt_id")
            sensitive_ids = []
            if isinstance(result.evidence, dict):
                sensitive_ids = list(result.evidence.get("sensitive_ids", []))
            event = self._event(
                case=case,
                run_id=run_id,
                event_id=event_id,
                sequence=sequence,
                step=step,
                arguments=arguments,
                decision=decision,
                parent=parent,
                status=result.status,
                summary=result.summary,
                evidence=result.evidence,
            )
            events.append(event)
            step_outputs[step.id] = result.output
            step_event_ids[step.id] = event_id
            actions.append(
                ActionOutcome(
                    step_id=step.id,
                    tool=step.tool,
                    origin=step.origin,
                    purpose=step.purpose,
                    decision="allow",
                    reason_code=decision.reason_code,
                    status=result.status,
                    event_id=event_id,
                    receipt_id=receipt_id,
                    sensitive_ids=sensitive_ids,
                )
            )

        return RunResult(
            case=case,
            profile=self.profile,
            run_id=run_id,
            events=events,
            receipts=receiver.receipts,
            actions=actions,
            errors=errors,
            clock=self.clock,
        )

    def _event(
        self,
        *,
        case: TestCase,
        run_id: str,
        event_id: str,
        sequence: int,
        step: PlanStep,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        parent: str | None,
        status: str,
        summary: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "run_id": run_id,
            "event_id": event_id,
            "sequence": sequence,
            "timestamp": self.clock.now(),
            "parent_event_id": parent,
            "case_id": case.id,
            "step_id": step.id,
            "profile": self.profile,
            "principal": case.principal.as_dict(),
            "tool": step.tool,
            "origin": step.origin,
            "args": _safe_arguments(step.tool, arguments, self.redactor),
            "permission": {
                "decision": "allow" if decision.allow else "deny",
                "reason_code": decision.reason_code,
                "reason": decision.reason,
                "policy_version": decision.policy_version,
            },
            "result": {
                "status": status,
                "summary": summary,
                "evidence": self.redactor.redact_structure(evidence),
            },
        }


def run_case(case: TestCase, *, workspace: Path, sandbox: Path, scanner: SecretScanner, profile: str) -> RunResult:
    return CaseRunner(
        workspace=workspace,
        sandbox=sandbox,
        scanner=scanner,
        profile=profile,
    ).run(case)
