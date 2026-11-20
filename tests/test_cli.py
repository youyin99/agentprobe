from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import REPO_ROOT


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "agentprobe", *args],
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
    )


def test_cli_validate():
    result = _run("validate")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["counts"]["attack"] == 15


def test_cli_run_writes_artifacts(tmp_path):
    output = tmp_path / "report"
    result = _run("run", "--out", str(output), "--strict")
    assert result.returncode == 0, result.stderr
    for name in (
        "agentprobe-report.json",
        "agentprobe-report.html",
        "events.jsonl",
        "receipts.jsonl",
    ):
        assert (output / name).is_file(), name
    report = json.loads((output / "agentprobe-report.json").read_text(encoding="utf-8"))
    assert report["summary"]["differential_attack_cases"] == 15
    for path in output.iterdir():
        if path.suffix in {".json", ".jsonl", ".html"}:
            assert "DEMOSECRET-" not in path.read_text(encoding="utf-8")


def test_cli_unknown_case_is_an_input_error(tmp_path):
    result = _run(
        "run",
        "--case",
        "does-not-exist",
        "--no-require-full-library",
        "--out",
        str(tmp_path),
    )
    assert result.returncode == 2
    assert "unknown case" in result.stderr
