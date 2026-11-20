from __future__ import annotations

import hashlib
import html
import json
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import __version__
from .case_loader import ATTACK_CATEGORIES
from .models import TestCase
from .runner import RunResult
from .secrets import Redactor, SecretScanner


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(path.rglob("*")):
        if file.is_file() and "__pycache__" not in file.parts:
            digest.update(file.relative_to(path).as_posix().encode())
            digest.update(file.read_bytes())
    return digest.hexdigest()


def build_report(
    *,
    cases: list[TestCase],
    evaluations: dict[str, dict[str, Any]],
    runs: dict[str, dict[str, RunResult]],
    scanner: SecretScanner,
    workspace: Path,
    cases_dir: Path,
    artifacts: dict[str, str],
) -> dict[str, Any]:
    from .tools import utc_now

    categories: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "attack": 0,
            "baseline_risk_demonstrated": 0,
            "hardened_protected": 0,
            "hardened_vulnerable": 0,
            "hardened_uncertain": 0,
            "differential": 0,
        }
    )
    attack_cases = 0
    benign_cases = 0
    benign_passed_both = 0
    differential_cases = 0
    hardened_uncertain = 0
    errors = 0
    for case in cases:
        if case.kind == "attack":
            attack_cases += 1
            categories[case.category]["attack"] += 1
        else:
            benign_cases += 1
        evaluation = evaluations[case.id]
        baseline = evaluation["profiles"]["baseline"]
        hardened = evaluation["profiles"]["hardened"]
        errors += baseline["error_count"] + hardened["error_count"]
        if case.kind == "attack":
            if baseline["verdict"] == "risk_demonstrated":
                categories[case.category]["baseline_risk_demonstrated"] += 1
            if hardened["verdict"] == "protected":
                categories[case.category]["hardened_protected"] += 1
            if hardened["verdict"] == "vulnerable":
                categories[case.category]["hardened_vulnerable"] += 1
            if hardened["verdict"] == "uncertain":
                categories[case.category]["hardened_uncertain"] += 1
                hardened_uncertain += 1
            if evaluation["differential"]:
                categories[case.category]["differential"] += 1
                differential_cases += 1
        elif baseline["verdict"] == "passed" and hardened["verdict"] == "passed":
            benign_passed_both += 1

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "report_type": "agentprobe",
        "agentprobe_version": __version__,
        "generated_at": utc_now(),
        "run_id": f"report-{uuid.uuid4().hex}",
        "mode": "offline_deterministic",
        "model": {
            "provider": "offline",
            "name": "deterministic-scenario-adapter",
            "external_calls": False,
        },
        "configuration": {
            "profiles": ["baseline", "hardened"],
            "policy_versions": {
                "baseline": "agentprobe-baseline-1.0",
                "hardened": "agentprobe-hardened-1.0",
            },
            "case_library_sha256": _sha256(cases_dir),
            "workspace_sha256": _sha256(workspace),
            "case_directory": cases_dir.name,
        },
        "summary": {
            "cases": len(cases),
            "attack_cases": attack_cases,
            "benign_cases": benign_cases,
            "categories": {
                category: dict(categories[category]) for category in ATTACK_CATEGORIES
            },
            "benign_passed_both": benign_passed_both,
            "hardened_uncertain": hardened_uncertain,
            "differential_attack_cases": differential_cases,
            "errors": errors,
        },
        "cases": [
            {
                **evaluations[case.id],
                "evidence_log": artifacts.get("events"),
            }
            for case in cases
        ],
        "artifacts": dict(artifacts),
        "limitations": [
            "Offline deterministic test adapter; this is not a live model security evaluation.",
            "The baseline profile intentionally lacks controls but remains constrained to the synthetic fixture sandbox.",
            "Network egress is simulated through a process-local receiver; no external service is contacted.",
        ],
    }
    return Redactor(scanner).redact_structure(report)


def write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_html(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")


def render_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    case_rows = []
    details = []
    verdict_class = {
        "protected": "good",
        "passed": "good",
        "risk_demonstrated": "bad",
        "vulnerable": "bad",
        "failed": "bad",
        "uncertain": "warn",
        "skipped": "warn",
        "error": "bad",
    }
    for case in report["cases"]:
        baseline = case["profiles"]["baseline"]["verdict"]
        hardened = case["profiles"]["hardened"]["verdict"]
        differential = case.get("differential")
        diff_text = "yes" if differential else ("n/a" if differential is None else "no")
        case_rows.append(
            "<tr>"
            f"<td><code>{html.escape(case['id'])}</code></td>"
            f"<td>{html.escape(case['title'])}</td>"
            f"<td>{html.escape(case['category'])}</td>"
            f"<td><span class='badge {verdict_class.get(baseline, '')}'>{html.escape(baseline)}</span></td>"
            f"<td><span class='badge {verdict_class.get(hardened, '')}'>{html.escape(hardened)}</span></td>"
            f"<td>{html.escape(diff_text)}</td>"
            "</tr>"
        )
        details.append(_case_detail(case, verdict_class))
    category_rows = []
    for category, stats in summary["categories"].items():
        category_rows.append(
            "<tr>"
            f"<td>{html.escape(category)}</td>"
            f"<td>{stats['attack']}</td>"
            f"<td>{stats['baseline_risk_demonstrated']}</td>"
            f"<td>{stats['hardened_protected']}</td>"
            f"<td>{stats['differential']}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentProbe Security Report</title>
<style>
:root {{
  color-scheme: light;
  --bg: #f5f3ee;
  --panel: #fffdf8;
  --ink: #1d2524;
  --muted: #64706d;
  --line: #d9d5cc;
  --accent: #173f5f;
  --good: #1b6b3a;
  --good-bg: #e2f2e6;
  --bad: #972f2f;
  --bad-bg: #f8e1df;
  --warn: #8a5a00;
  --warn-bg: #fbecd2;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.55 "Segoe UI", system-ui, sans-serif; }}
header {{ background: var(--accent); color: white; padding: 38px max(24px, 6vw) 28px; }}
header .eyebrow {{ text-transform: uppercase; letter-spacing: .12em; font-size: 12px; opacity: .72; }}
h1 {{ margin: 8px 0 4px; font-size: clamp(28px, 4vw, 46px); line-height: 1.05; }}
header p {{ max-width: 850px; margin: 8px 0 0; opacity: .84; }}
main {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: 12px; margin: -48px 0 24px; }}
.card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; box-shadow: 0 6px 24px rgba(23,63,95,.08); }}
.card .num {{ display: block; font-size: 30px; font-weight: 700; color: var(--accent); }}
.card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }}
section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 20px; margin: 18px 0; overflow: hidden; }}
h2 {{ margin: 0 0 14px; font-size: 20px; }}
table {{ width: 100%; border-collapse: collapse; display: block; overflow-x: auto; }}
th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }}
code {{ background: #eeeae2; padding: 1px 4px; border-radius: 4px; font-size: .9em; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
.good {{ background: var(--good-bg); color: var(--good); }}
.bad {{ background: var(--bad-bg); color: var(--bad); }}
.warn {{ background: var(--warn-bg); color: var(--warn); }}
details {{ border-top: 1px solid var(--line); padding: 12px 0; }}
details:first-of-type {{ border-top: 0; }}
summary {{ cursor: pointer; font-weight: 600; }}
.subtle {{ color: var(--muted); }}
.actions {{ margin: 10px 0 6px; }}
.verdict {{ font-weight: 600; }}
footer {{ color: var(--muted); font-size: 12px; margin: 22px 0 40px; }}
@media (max-width: 640px) {{
  main {{ padding: 16px; }}
  .cards {{ margin-top: 16px; }}
  header {{ padding: 28px 18px 24px; }}
}}
</style>
</head>
<body>
<header>
  <div class="eyebrow">Offline deterministic evaluation</div>
  <h1>AgentProbe Security Report</h1>
  <p>Same attack cases, two policies. Baseline demonstrates synthetic risk; hardened applies instruction isolation, role scopes, egress allowlisting and synthetic-secret detection.</p>
</header>
<main>
  <div class="cards">
    <div class="card"><span class="num">{summary['attack_cases']}</span><span class="label">Attack cases</span></div>
    <div class="card"><span class="num">{summary['benign_cases']}</span><span class="label">Benign cases</span></div>
    <div class="card"><span class="num">{summary['differential_attack_cases']}</span><span class="label">Differential</span></div>
    <div class="card"><span class="num">{summary['hardened_uncertain']}</span><span class="label">Uncertain</span></div>
    <div class="card"><span class="num">{summary['benign_passed_both']}</span><span class="label">Benign pass both</span></div>
  </div>
  <section>
    <h2>Category coverage</h2>
    <table>
      <thead><tr><th>Category</th><th>Cases</th><th>Baseline risk</th><th>Hardened protected</th><th>Differential</th></tr></thead>
      <tbody>{''.join(category_rows)}</tbody>
    </table>
  </section>
  <section>
    <h2>Case results</h2>
    <table>
      <thead><tr><th>ID</th><th>Case</th><th>Category</th><th>Baseline</th><th>Hardened</th><th>Differential</th></tr></thead>
      <tbody>{''.join(case_rows)}</tbody>
    </table>
  </section>
  <section>
    <h2>Evidence by case</h2>
    {''.join(details)}
  </section>
  <section>
    <h2>Scope and limitations</h2>
    <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in report.get('limitations', []))}</ul>
    <p class="subtle">Artifacts: {html.escape(json.dumps(report.get('artifacts', {}), ensure_ascii=False))}. Generated {html.escape(report['generated_at'])}.</p>
  </section>
  <footer>AgentProbe {html.escape(report['agentprobe_version'])} · synthetic data only · no network egress</footer>
</main>
</body>
</html>
"""


def _case_detail(case: dict[str, Any], verdict_class: dict[str, str]) -> str:
    chunks = [
        "<details>",
        f"<summary><code>{html.escape(case['id'])}</code> {html.escape(case['title'])} "
        f"<span class='badge {verdict_class.get(case['profiles']['baseline']['verdict'], '')}'>baseline: {html.escape(case['profiles']['baseline']['verdict'])}</span> "
        f"<span class='badge {verdict_class.get(case['profiles']['hardened']['verdict'], '')}'>hardened: {html.escape(case['profiles']['hardened']['verdict'])}</span></summary>",
        f"<p class='subtle'>{html.escape(case['task'])}</p>",
        "<p><strong>Forbidden:</strong> "
        + html.escape("; ".join(case.get("expected", {}).get("forbidden_behavior", [])))
        + "</p>",
    ]
    for profile in ("baseline", "hardened"):
        profile_data = case["profiles"][profile]
        chunks.append(f"<h3>{profile}</h3>")
        chunks.append("<table class='actions'><thead><tr><th>Step</th><th>Tool</th><th>Origin</th><th>Decision</th><th>Status</th><th>Event</th></tr></thead><tbody>")
        for action in profile_data["actions"]:
            chunks.append(
                "<tr>"
                f"<td>{html.escape(action['step_id'])}</td>"
                f"<td>{html.escape(action['tool'])}</td>"
                f"<td>{html.escape(action['origin'])}</td>"
                f"<td>{html.escape(action['decision'])} / {html.escape(action['reason_code'])}</td>"
                f"<td>{html.escape(action['status'])}</td>"
                f"<td><code>{html.escape(action['event_id'])}</code></td>"
                "</tr>"
            )
        chunks.append("</tbody></table>")
        chunks.append("<table><thead><tr><th>Assertion</th><th>Status</th><th>Summary</th><th>Evidence</th></tr></thead><tbody>")
        for assertion in profile_data["assertions"]:
            evidence = assertion.get("evidence", {})
            chunks.append(
                "<tr>"
                f"<td><code>{html.escape(assertion['id'])}</code></td>"
                f"<td><span class='badge {verdict_class.get(assertion['status'], '')}'>{html.escape(assertion['status'])}</span></td>"
                f"<td>{html.escape(assertion['summary'])}</td>"
                f"<td><code>{html.escape(json.dumps(evidence, ensure_ascii=False))}</code></td>"
                "</tr>"
            )
        chunks.append("</tbody></table>")
    if case["profiles"]["baseline"].get("errors"):
        chunks.append("<p class='bad'><strong>Baseline errors:</strong> " + html.escape("; ".join(case["profiles"]["baseline"]["errors"])) + "</p>")
    if case["profiles"]["hardened"].get("errors"):
        chunks.append("<p class='bad'><strong>Hardened errors:</strong> " + html.escape("; ".join(case["profiles"]["hardened"]["errors"])) + "</p>")
    chunks.append("</details>")
    return "".join(chunks)
