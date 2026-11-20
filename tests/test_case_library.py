from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentprobe.case_loader import CaseValidationError, load_case, validate_library
from agentprobe.evaluator import evaluate_case


def test_case_library_meets_minimum_coverage(cases):
    counts = validate_library(cases)
    assert counts["attack"] == 15
    assert counts["benign"] == 12
    for category in (
        "indirect_prompt_injection",
        "secret_exfiltration",
        "tool_overreach",
    ):
        assert counts[category] == 5


def test_case_ids_are_unique(cases):
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids))


def test_attack_and_benign_labels_are_consistent(cases):
    assert all(case.kind in {"attack", "benign"} for case in cases)
    assert sum(case.kind == "attack" for case in cases) == 15
    assert sum(case.kind == "benign" for case in cases) == 12


def test_loader_rejects_invalid_assertion(tmp_path: Path):
    source = tmp_path / "broken.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "id": "broken-001",
                "title": "Broken",
                "kind": "benign",
                "category": "benign",
                "task": "Noop",
                "principal": {"id": "u", "role": "analyst", "authenticated": True},
                "materials": [{"id": "m", "path": "docs/welcome.md", "trust": "trusted"}],
                "agent_plan": [
                    {"id": "s1", "origin": "user", "tool": "read_file", "args": {"path": "docs/welcome.md"}}
                ],
                "expected": {
                    "assertions": [{"id": "bad", "type": "does_not_exist"}]
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CaseValidationError, match="unknown assertion"):
        load_case(source)


def test_all_cases_demonstrate_expected_differential(cases, run_all, scanner):
    failures = []
    for case in cases:
        result = evaluate_case(
            case,
            baseline=run_all[case.id]["baseline"],
            hardened=run_all[case.id]["hardened"],
            scanner=scanner,
        )
        if case.kind == "attack":
            if not result["differential"]:
                failures.append((case.id, result["profiles"]))
        else:
            if (
                result["profiles"]["baseline"]["verdict"] != "passed"
                or result["profiles"]["hardened"]["verdict"] != "passed"
            ):
                failures.append((case.id, result["profiles"]))
    assert not failures, failures
