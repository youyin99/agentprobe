from __future__ import annotations

import json

from agentprobe.secrets import SYNTHETIC_SECRET_RE


def test_baseline_and_hardened_runs_are_redacted(run_all, scanner):
    for profile_runs in run_all.values():
        for run in profile_runs.values():
            text = "\n".join(json.dumps(event, ensure_ascii=False) for event in run.events)
            assert "DEMOSECRET-" not in text
            assert not SYNTHETIC_SECRET_RE.search(text)
            assert not scanner.scan(text)
            for event in run.events:
                assert event["schema_version"] == "1.0"
                assert event["run_id"]
                assert event["event_id"]
                assert event["timestamp"]
                assert event["principal"]["id"]
                assert event["tool"]
                assert event["permission"]["decision"] in {"allow", "deny"}
                assert event["result"]["status"] in {"ok", "denied", "error"}
            for receipt in run.receipts:
                sanitized = json.dumps(receipt.sanitized(), ensure_ascii=False)
                assert "DEMOSECRET-" not in sanitized
                assert "content" not in receipt.sanitized()


def test_baseline_leaks_a_receipt_but_hardened_does_not(case_map, run_all, scanner):
    baseline = run_all["exfil-001"]["baseline"]
    hardened = run_all["exfil-001"]["hardened"]
    assert baseline.receipts
    assert "beta-partner-key" in baseline.aggregate_sensitive_ids(scanner)
    assert not hardened.receipts
    assert any(action.decision == "deny" for action in hardened.actions)


def test_send_event_is_linked_to_read_event(run_all):
    events = run_all["ipi-003"]["baseline"].events
    read_event = next(event for event in events if event["tool"] == "read_file")
    send_event = next(event for event in events if event["tool"] == "send_external")
    assert send_event["parent_event_id"] == read_event["event_id"]
    assert read_event["result"]["evidence"]["source"]["origin"] == "external"


def test_injected_action_is_denied_by_hardened_policy(run_all):
    events = run_all["ipi-001"]["hardened"].events
    send = next(event for event in events if event["tool"] == "send_external")
    assert send["permission"]["decision"] == "deny"
    assert send["permission"]["reason_code"] == "untrusted_instruction"
    assert send["result"]["status"] == "denied"


def test_path_traversal_and_role_scope_are_blocked(run_all):
    traversal = run_all["overreach-001"]["hardened"].events[0]
    assert traversal["permission"]["reason_code"] == "path_traversal"
    finance = run_all["overreach-002"]["hardened"].events[0]
    assert finance["permission"]["reason_code"] == "path_not_allowed_for_role"


def test_all_attack_cases_and_benign_functionality(cases, run_all, scanner):
    from agentprobe.evaluator import evaluate_case

    for case in cases:
        result = evaluate_case(
            case,
            baseline=run_all[case.id]["baseline"],
            hardened=run_all[case.id]["hardened"],
            scanner=scanner,
        )
        if case.kind == "attack":
            assert result["profiles"]["baseline"]["verdict"] == "risk_demonstrated", case.id
            assert result["profiles"]["hardened"]["verdict"] == "protected", case.id
            assert result["differential"] is True, case.id
        else:
            assert result["profiles"]["baseline"]["verdict"] == "passed", case.id
            assert result["profiles"]["hardened"]["verdict"] == "passed", case.id
