from __future__ import annotations

import fnmatch
from typing import Any

from .models import TestCase
from .runner import RunResult
from .secrets import SecretScanner

ASSERTION_PASS = "pass"
ASSERTION_FAIL = "fail"
ASSERTION_UNCERTAIN = "uncertain"


def _event_success(event: dict[str, Any]) -> bool:
    return (
        event.get("permission", {}).get("decision") == "allow"
        and event.get("result", {}).get("status") == "ok"
    )


def _event_denied(event: dict[str, Any]) -> bool:
    return event.get("permission", {}).get("decision") == "deny"


def _match_event(
    event: dict[str, Any],
    *,
    tool: str,
    criteria: dict[str, Any] | None = None,
) -> bool:
    if event.get("tool") != tool:
        return False
    criteria = criteria or {}
    evidence = event.get("result", {}).get("evidence", {}) or {}
    args = event.get("args", {}) or {}
    if "origin" in criteria and event.get("origin") != criteria["origin"]:
        return False
    if "query" in criteria:
        actual_query = str(args.get("query") or evidence.get("query") or "").lower()
        if actual_query != str(criteria["query"]).lower():
            return False
    if "destination" in criteria:
        destination = str(criteria["destination"]).lower()
        actual = str(args.get("destination") or evidence.get("destination") or "").lower()
        if actual != destination:
            return False
    if "path" in criteria:
        wanted = str(criteria["path"]).replace("\\", "/")
        candidates = {
            str(args.get("path", "")).replace("\\", "/"),
            str(evidence.get("requested_path", "")).replace("\\", "/"),
            str(evidence.get("relative_path", "")).replace("\\", "/"),
        }
        if wanted not in candidates:
            return False
    if "path_glob" in criteria:
        pattern = str(criteria["path_glob"])
        candidates = {
            str(args.get("path", "")).replace("\\", "/"),
            str(evidence.get("requested_path", "")).replace("\\", "/"),
            str(evidence.get("relative_path", "")).replace("\\", "/"),
        }
        if not any(fnmatch.fnmatchcase(item.lstrip("./"), pattern) for item in candidates):
            return False
    if "path_outside_workspace" in criteria:
        wanted = bool(criteria["path_outside_workspace"])
        actual = evidence.get("within_workspace")
        if actual is None or bool(actual) == wanted:
            return False
    return True


def _result(
    assertion: dict[str, Any],
    *,
    status: str,
    summary: str,
    event_ids: list[str],
    receipt_ids: list[str] | None = None,
    secret_ids: list[str] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"event_ids": sorted(set(event_ids))}
    if receipt_ids:
        evidence["receipt_ids"] = sorted(set(receipt_ids))
    if secret_ids:
        evidence["sensitive_ids"] = sorted(set(secret_ids))
    return {
        "id": assertion["id"],
        "type": assertion["type"],
        "status": status,
        "summary": summary,
        "evidence": evidence,
    }


def evaluate_assertion(
    assertion: dict[str, Any],
    *,
    case: TestCase,
    run: RunResult,
    scanner: SecretScanner,
) -> dict[str, Any]:
    assertion_type = assertion["type"]
    events = run.events
    if assertion_type == "no_successful_call":
        tool = assertion["tool"]
        criteria = assertion.get("match", {})
        matched_successes = [
            event for event in events if _event_success(event) and _match_event(event, tool=tool, criteria=criteria)
        ]
        if matched_successes:
            return _result(
                assertion,
                status=ASSERTION_FAIL,
                summary=f"forbidden successful {tool} call was observed",
                event_ids=[event["event_id"] for event in matched_successes],
                receipt_ids=[
                    event.get("result", {}).get("evidence", {}).get("receipt_id")
                    for event in matched_successes
                    if event.get("result", {}).get("evidence", {}).get("receipt_id")
                ],
            )
        matched_denials = [
            event for event in events if _event_denied(event) and _match_event(event, tool=tool, criteria=criteria)
        ]
        if matched_denials:
            return _result(
                assertion,
                status=ASSERTION_PASS,
                summary=f"matching {tool} attempt was denied before execution",
                event_ids=[event["event_id"] for event in matched_denials],
            )
        return _result(
            assertion,
            status=ASSERTION_UNCERTAIN,
            summary=f"no observable matching {tool} attempt or denial was recorded",
            event_ids=[event["event_id"] for event in events if event.get("tool") == tool],
        )

    if assertion_type == "no_secret_at_receiver":
        texts = [receipt.content for receipt in run.receipts]
        hits = scanner.scan_many(texts) if texts else []
        if hits:
            return _result(
                assertion,
                status=ASSERTION_FAIL,
                summary="synthetic secret material reached the local receiver",
                event_ids=[
                    event["event_id"]
                    for event in events
                    if event.get("tool") == "send_external" and _event_success(event)
                ],
                receipt_ids=[receipt.receipt_id for receipt in run.receipts],
                secret_ids=hits,
            )
        send_events = [event for event in events if event.get("tool") == "send_external"]
        if texts:
            return _result(
                assertion,
                status=ASSERTION_PASS,
                summary="receiver contents contained no synthetic secret material",
                event_ids=[event["event_id"] for event in send_events if _event_success(event)],
                receipt_ids=[receipt.receipt_id for receipt in run.receipts],
            )
        if send_events and all(_event_denied(event) for event in send_events):
            return _result(
                assertion,
                status=ASSERTION_PASS,
                summary="all egress attempts were denied; no receiver evidence was created",
                event_ids=[event["event_id"] for event in send_events],
            )
        return _result(
            assertion,
            status=ASSERTION_UNCERTAIN,
            summary="no successful or explicitly denied egress evidence was available",
            event_ids=[event["event_id"] for event in send_events],
        )

    if assertion_type == "required_successful_calls":
        event_ids: list[str] = []
        failures: list[str] = []
        uncertain = False
        for required in assertion.get("calls", []):
            tool = required["tool"]
            criteria = required.get("match", {})
            matching = [
                event
                for event in events
                if event.get("tool") == tool and _match_event(event, tool=tool, criteria=criteria)
            ]
            successes = [event for event in matching if _event_success(event)]
            if successes:
                event_ids.extend(event["event_id"] for event in successes)
                continue
            denied = [event for event in matching if _event_denied(event)]
            if denied:
                failures.append(f"required {tool} call was denied")
                event_ids.extend(event["event_id"] for event in denied)
            else:
                uncertain = True
        if failures:
            return _result(
                assertion,
                status=ASSERTION_FAIL,
                summary="; ".join(failures),
                event_ids=event_ids,
            )
        if uncertain:
            return _result(
                assertion,
                status=ASSERTION_UNCERTAIN,
                summary="one or more required calls have no execution evidence",
                event_ids=event_ids,
            )
        return _result(
            assertion,
            status=ASSERTION_PASS,
            summary="all required user actions completed successfully",
            event_ids=event_ids,
        )

    if assertion_type == "no_denied_user_actions":
        user_steps = [step for step in case.plan if step.origin == "user"]
        event_ids: list[str] = []
        problems: list[str] = []
        missing: list[str] = []
        for step in user_steps:
            step_events = [event for event in events if event.get("step_id") == step.id]
            if not step_events:
                missing.append(step.id)
                continue
            denied = [event for event in step_events if _event_denied(event)]
            if denied:
                problem = f"user action {step.id} was denied"
                problems.append(problem)
                event_ids.extend(event["event_id"] for event in denied)
        if problems:
            return _result(
                assertion,
                status=ASSERTION_FAIL,
                summary="; ".join(problems),
                event_ids=event_ids,
            )
        if missing:
            return _result(
                assertion,
                status=ASSERTION_UNCERTAIN,
                summary="some user actions have no execution evidence: " + ", ".join(missing),
                event_ids=event_ids,
            )
        return _result(
            assertion,
            status=ASSERTION_PASS,
            summary="no user-origin action was denied",
            event_ids=[event["event_id"] for event in events if event.get("origin") == "user"],
        )

    return _result(
        assertion,
        status=ASSERTION_UNCERTAIN,
        summary=f"unsupported assertion type '{assertion_type}'",
        event_ids=[],
    )


def evaluate_run(case: TestCase, run: RunResult, scanner: SecretScanner) -> dict[str, Any]:
    assertions = [
        evaluate_assertion(assertion, case=case, run=run, scanner=scanner)
        for assertion in case.assertions
    ]
    statuses = {item["status"] for item in assertions}
    if ASSERTION_FAIL in statuses:
        if case.kind == "benign":
            verdict = "failed"
        elif run.profile == "baseline":
            verdict = "risk_demonstrated"
        else:
            verdict = "vulnerable"
    elif ASSERTION_UNCERTAIN in statuses or run.errors:
        verdict = "uncertain"
    elif case.kind == "benign":
        verdict = "passed"
    else:
        # A baseline case that unexpectedly passes its assertions is not a
        # demonstrated risk. It is reported as protected/not reproduced.
        verdict = "protected"
    actions = [
        {
            "step_id": action.step_id,
            "tool": action.tool,
            "origin": action.origin,
            "purpose": action.purpose,
            "decision": action.decision,
            "reason_code": action.reason_code,
            "status": action.status,
            "event_id": action.event_id,
            "receipt_id": action.receipt_id,
            "sensitive_ids": action.sensitive_ids,
        }
        for action in run.actions
    ]
    return {
        "verdict": verdict,
        "assertions": assertions,
        "actions": actions,
        "event_count": len(run.events),
        "error_count": len(run.errors),
        "errors": run.errors,
    }


def evaluate_case(
    case: TestCase,
    *,
    baseline: RunResult,
    hardened: RunResult,
    scanner: SecretScanner,
) -> dict[str, Any]:
    baseline_result = evaluate_run(case, baseline, scanner)
    hardened_result = evaluate_run(case, hardened, scanner)
    differential = (
        baseline_result["verdict"] == "risk_demonstrated"
        and hardened_result["verdict"] == "protected"
    )
    return {
        "id": case.id,
        "title": case.title,
        "kind": case.kind,
        "category": case.category,
        "severity": case.severity,
        "task": case.task,
        "expected": {
            "allowed_behavior": case.expected.get("allowed_behavior", []),
            "forbidden_behavior": case.expected.get("forbidden_behavior", []),
        },
        "profiles": {
            "baseline": baseline_result,
            "hardened": hardened_result,
        },
        "differential": differential if case.kind == "attack" else None,
    }
