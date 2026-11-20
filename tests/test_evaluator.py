from __future__ import annotations

from agentprobe.evaluator import (
    ASSERTION_FAIL,
    ASSERTION_PASS,
    ASSERTION_UNCERTAIN,
    evaluate_assertion,
    evaluate_case,
    evaluate_run,
)
from agentprobe.runner import MonotonicClock, RunResult


def _assertion(case, assertion_id):
    return next(item for item in case.assertions if item["id"] == assertion_id)


def test_judge_marks_correct_protection(case_map, run_all, scanner):
    case = case_map["exfil-002"]
    result = evaluate_assertion(
        _assertion(case, "no-collector-egress"),
        case=case,
        run=run_all[case.id]["hardened"],
        scanner=scanner,
    )
    assert result["status"] == ASSERTION_PASS


def test_judge_marks_observed_violation(case_map, run_all, scanner):
    case = case_map["exfil-002"]
    result = evaluate_assertion(
        _assertion(case, "no-secret-at-receiver"),
        case=case,
        run=run_all[case.id]["baseline"],
        scanner=scanner,
    )
    assert result["status"] == ASSERTION_FAIL
    assert result["evidence"]["receipt_ids"]
    assert "alpha-service-key" in result["evidence"]["sensitive_ids"]


def test_judge_marks_insufficient_evidence_uncertain(case_map, scanner):
    case = case_map["benign-001"]
    empty = RunResult(
        case=case,
        profile="hardened",
        run_id="run-empty",
        events=[],
        receipts=[],
        actions=[],
        errors=[],
        clock=MonotonicClock(),
    )
    result = evaluate_assertion(
        _assertion(case, "required-user-work"),
        case=case,
        run=empty,
        scanner=scanner,
    )
    assert result["status"] == ASSERTION_UNCERTAIN
    verdict = evaluate_run(case, empty, scanner)
    assert verdict["verdict"] == "uncertain"


def test_judge_does_not_treat_missing_egress_evidence_as_success(case_map, scanner):
    case = case_map["exfil-002"]
    empty = RunResult(
        case=case,
        profile="hardened",
        run_id="run-empty",
        events=[],
        receipts=[],
        actions=[],
        errors=[],
        clock=MonotonicClock(),
    )
    result = evaluate_assertion(
        _assertion(case, "no-secret-at-receiver"),
        case=case,
        run=empty,
        scanner=scanner,
    )
    assert result["status"] == ASSERTION_UNCERTAIN
    assert "no successful or explicitly denied egress" in result["summary"]


def test_judge_records_execution_errors_as_uncertain(case_map, scanner):
    case = case_map["benign-002"]
    empty = RunResult(
        case=case,
        profile="hardened",
        run_id="run-error",
        events=[],
        receipts=[],
        actions=[],
        errors=["s1: file does not exist"],
        clock=MonotonicClock(),
    )
    result = evaluate_case(
        case,
        baseline=empty,
        hardened=empty,
        scanner=scanner,
    )
    assert result["profiles"]["hardened"]["verdict"] == "uncertain"


def test_attack_verdict_differs_between_profiles(case_map, run_all, scanner):
    case = case_map["ipi-003"]
    result = evaluate_case(
        case,
        baseline=run_all[case.id]["baseline"],
        hardened=run_all[case.id]["hardened"],
        scanner=scanner,
    )
    assert result["profiles"]["baseline"]["verdict"] == "risk_demonstrated"
    assert result["profiles"]["hardened"]["verdict"] == "protected"
    assert result["differential"] is True
