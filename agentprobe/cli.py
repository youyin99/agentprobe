from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .case_loader import load_cases, validate_library
from .errors import AgentProbeError
from .evaluator import evaluate_case
from .reports import build_report, write_html, write_json
from .runner import CaseRunner
from .secrets import SecretCatalog, SecretScanner


def _default_sandbox(workspace: Path) -> Path:
    return workspace.parent


def _load_scanner(workspace: Path, catalog_path: Path | None) -> SecretScanner:
    path = catalog_path or workspace / "config" / "synthetic_secrets.json"
    if path.exists():
        return SecretScanner(SecretCatalog.load(path))
    return SecretScanner()


def _write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in items),
        encoding="utf-8",
    )


def _ensure_no_plaintext(paths: list[Path], scanner: SecretScanner) -> None:
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        hits = scanner.scan(text, include_encoded=True)
        if hits:
            raise AgentProbeError(
                f"refusing to publish artifact {path.name}: plaintext synthetic secret detected"
            )


def command_run(args: argparse.Namespace) -> int:
    cases_dir = Path(args.cases)
    workspace = Path(args.workspace)
    sandbox = Path(args.sandbox) if args.sandbox else _default_sandbox(workspace)
    output_dir = Path(args.out)
    cases = load_cases(cases_dir)
    if args.case:
        selected = set(args.case)
        available = {case.id for case in cases}
        missing = selected - available
        if missing:
            raise AgentProbeError(f"unknown case id(s): {', '.join(sorted(missing))}")
        cases = [case for case in cases if case.id in selected]
    if args.require_full_library:
        validate_library(cases)
    scanner = _load_scanner(workspace, Path(args.secret_catalog) if args.secret_catalog else None)

    evaluations: dict[str, dict[str, Any]] = {}
    runs: dict[str, dict[str, Any]] = {}
    all_events: list[dict[str, Any]] = []
    all_receipts: list[dict[str, Any]] = []
    for case in cases:
        profiled_runs = {}
        for profile in ("baseline", "hardened"):
            runner = CaseRunner(
                workspace=workspace,
                sandbox=sandbox,
                scanner=scanner,
                profile=profile,
            )
            run = runner.run(case)
            profiled_runs[profile] = run
            all_events.extend(run.events)
            all_receipts.extend(run.sanitized_receipts(scanner))
        runs[case.id] = profiled_runs
        evaluations[case.id] = evaluate_case(
            case,
            baseline=profiled_runs["baseline"],
            hardened=profiled_runs["hardened"],
            scanner=scanner,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    events_path = output_dir / "events.jsonl"
    receipts_path = output_dir / "receipts.jsonl"
    report_path = output_dir / "agentprobe-report.json"
    html_path = output_dir / "agentprobe-report.html"
    _write_jsonl(events_path, all_events)
    _write_jsonl(receipts_path, all_receipts)

    report = build_report(
        cases=cases,
        evaluations=evaluations,
        runs=runs,
        scanner=scanner,
        workspace=workspace,
        cases_dir=cases_dir,
        artifacts={
            "events": events_path.name,
            "receipts": receipts_path.name,
        },
    )
    write_json(report_path, report)
    write_html(html_path, report)
    _ensure_no_plaintext([events_path, receipts_path, report_path, html_path], scanner)

    _print_summary(report, report_path)
    if args.strict:
        if (
            report["summary"]["hardened_uncertain"]
            or report["summary"]["errors"]
            or report["summary"]["differential_attack_cases"] != report["summary"]["attack_cases"]
            or report["summary"]["benign_passed_both"] != report["summary"]["benign_cases"]
        ):
            return 1
    return 0


def _print_summary(report: dict[str, Any], report_path: Path) -> None:
    summary = report["summary"]
    print(
        f"cases={summary['cases']} attack={summary['attack_cases']} benign={summary['benign_cases']} "
        f"differential={summary['differential_attack_cases']} "
        f"benign_pass_both={summary['benign_passed_both']} uncertain={summary['hardened_uncertain']} "
        f"errors={summary['errors']}"
    )
    for category, stats in summary["categories"].items():
        print(
            f"  {category}: cases={stats['attack']} "
            f"baseline_risk={stats['baseline_risk_demonstrated']} "
            f"hardened_protected={stats['hardened_protected']} "
            f"differential={stats['differential']}"
        )
    print(f"report={report_path}")


def command_validate(args: argparse.Namespace) -> int:
    cases = load_cases(Path(args.cases))
    counts = validate_library(cases)
    print(json.dumps({"ok": True, "cases": len(cases), "counts": counts}, indent=2))
    return 0


def command_list(args: argparse.Namespace) -> int:
    cases = load_cases(Path(args.cases))
    for case in cases:
        print(f"{case.id:20} {case.kind:7} {case.category:28} {case.title}")
    print(f"{len(cases)} case(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentprobe",
        description="Deterministic security evaluation for a synthetic document agent",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run baseline and hardened profiles and write a report")
    run.add_argument("--cases", default="fixtures/cases", help="case directory")
    run.add_argument("--workspace", default="fixtures/workspace", help="agent workspace")
    run.add_argument("--sandbox", default=None, help="fixture sandbox root (default: workspace parent)")
    run.add_argument("--secret-catalog", default=None, help="synthetic secret catalog JSON")
    run.add_argument("--out", default="reports", help="output directory")
    run.add_argument("--case", action="append", default=[], help="run only the given case id (repeatable)")
    run.add_argument(
        "--require-full-library",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="enforce the documented minimum case coverage",
    )
    run.add_argument("--strict", action="store_true", help="exit 1 when expected outcomes are not met")
    run.set_defaults(func=command_run)

    validate = sub.add_parser("validate", help="validate the case library and minimum coverage")
    validate.add_argument("--cases", default="fixtures/cases")
    validate.set_defaults(func=command_validate)

    list_command = sub.add_parser("list", help="list cases")
    list_command.add_argument("--cases", default="fixtures/cases")
    list_command.set_defaults(func=command_list)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (AgentProbeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
