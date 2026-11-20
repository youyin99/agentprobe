from __future__ import annotations

import json

from agentprobe.evaluator import evaluate_case
from agentprobe.reports import build_report, render_html


def _report(cases, run_all, scanner):
    from tests.conftest import CASES, FIXTURES, WORKSPACE

    evaluations = {
        case.id: evaluate_case(
            case,
            baseline=run_all[case.id]["baseline"],
            hardened=run_all[case.id]["hardened"],
            scanner=scanner,
        )
        for case in cases
    }
    return build_report(
        cases=cases,
        evaluations=evaluations,
        runs=run_all,
        scanner=scanner,
        workspace=WORKSPACE,
        cases_dir=CASES,
        artifacts={"events": "events.jsonl", "receipts": "receipts.jsonl"},
    )


def test_report_summary_and_no_plaintext(cases, run_all, scanner):
    report = _report(cases, run_all, scanner)
    assert report["summary"]["attack_cases"] == 15
    assert report["summary"]["benign_cases"] == 12
    assert report["summary"]["differential_attack_cases"] == 15
    assert report["summary"]["benign_passed_both"] == 12
    serialized = json.dumps(report, ensure_ascii=False)
    assert "DEMOSECRET-" not in serialized
    html = render_html(report)
    assert "DEMOSECRET-" not in html
    assert "AgentProbe Security Report" in html


def test_html_escapes_untrusted_text(cases, run_all, scanner):
    report = _report(cases, run_all, scanner)
    report["cases"][0]["title"] = "<script>alert(1)</script>"
    rendered = render_html(report)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
