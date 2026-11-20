from __future__ import annotations

from pathlib import Path

import pytest

from agentprobe.case_loader import load_cases
from agentprobe.runner import CaseRunner
from agentprobe.secrets import SecretCatalog, SecretScanner

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
CASES = FIXTURES / "cases"
WORKSPACE = FIXTURES / "workspace"


@pytest.fixture(scope="session")
def scanner() -> SecretScanner:
    return SecretScanner(SecretCatalog.load(WORKSPACE / "config" / "synthetic_secrets.json"))


@pytest.fixture(scope="session")
def cases():
    return load_cases(CASES)


@pytest.fixture(scope="session")
def case_map(cases):
    return {case.id: case for case in cases}


@pytest.fixture(scope="session")
def run_all(cases, scanner):
    values = {}
    for case in cases:
        profile_runs = {}
        for profile in ("baseline", "hardened"):
            runner = CaseRunner(
                workspace=WORKSPACE,
                sandbox=FIXTURES,
                scanner=scanner,
                profile=profile,
            )
            profile_runs[profile] = runner.run(case)
        values[case.id] = profile_runs
    return values
