from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .errors import CaseValidationError
from .models import Material, PlanStep, Principal, TestCase

ATTACK_CATEGORIES = (
    "indirect_prompt_injection",
    "secret_exfiltration",
    "tool_overreach",
)
ORIGINS = {"user", "injected", "system"}
KINDS = {"attack", "benign"}
ASSERTION_TYPES = {
    "no_successful_call",
    "no_secret_at_receiver",
    "required_successful_calls",
    "no_denied_user_actions",
}
TOOLS = {"search_documents", "read_file", "send_external"}
TEMPLATE_RE = re.compile(r"\{\{step:([A-Za-z0-9_-]+)\.output[^}]*\}\}")

REQUIRED_FIELDS = (
    "schema_version",
    "id",
    "title",
    "kind",
    "category",
    "task",
    "principal",
    "materials",
    "agent_plan",
    "expected",
)


def _fail(path: Path | str, message: str) -> None:
    raise CaseValidationError(f"{path}: {message}")


def _require_mapping(value: Any, path: Path | str, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, f"'{field}' must be an object")
    return value


def _parse_case(raw: dict[str, Any], path: Path) -> TestCase:
    for key in REQUIRED_FIELDS:
        if key not in raw:
            _fail(path, f"missing required field '{key}'")
    if raw["schema_version"] != "1.0":
        _fail(path, "schema_version must be '1.0'")
    if raw["kind"] not in KINDS:
        _fail(path, f"kind must be one of {sorted(KINDS)}")
    if raw["kind"] == "attack" and raw["category"] not in ATTACK_CATEGORIES:
        _fail(path, f"attack category must be one of {list(ATTACK_CATEGORIES)}")
    if raw["kind"] == "benign" and raw["category"] != "benign":
        _fail(path, "benign cases must use category='benign'")
    if not isinstance(raw["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", raw["id"]):
        _fail(path, "id must be a short kebab-case identifier")

    principal_raw = _require_mapping(raw["principal"], path, "principal")
    for key in ("id", "role", "authenticated"):
        if key not in principal_raw:
            _fail(path, f"principal missing '{key}'")
    if principal_raw["authenticated"] is not True:
        _fail(path, "fixture principal must be authenticated")
    principal = Principal(
        id=str(principal_raw["id"]),
        role=str(principal_raw["role"]),
        authenticated=True,
    )

    materials: list[Material] = []
    if not isinstance(raw["materials"], list) or not raw["materials"]:
        _fail(path, "materials must be a non-empty list")
    seen_material_ids: set[str] = set()
    for index, item in enumerate(raw["materials"]):
        item = _require_mapping(item, path, f"materials[{index}]")
        for key in ("id", "path", "trust"):
            if key not in item:
                _fail(path, f"materials[{index}] missing '{key}'")
        if item["id"] in seen_material_ids:
            _fail(path, f"duplicate material id '{item['id']}'")
        seen_material_ids.add(item["id"])
        if item["trust"] not in {"trusted", "untrusted"}:
            _fail(path, f"material '{item['id']}' has invalid trust")
        if not isinstance(item["path"], str) or Path(item["path"]).is_absolute():
            _fail(path, f"material '{item['id']}' path must be relative")
        materials.append(
            Material(
                id=item["id"],
                path=item["path"],
                trust=item["trust"],
                description=str(item.get("description", "")),
            )
        )

    plan_raw = raw["agent_plan"]
    if not isinstance(plan_raw, list) or not plan_raw:
        _fail(path, "agent_plan must be a non-empty list")
    plan: list[PlanStep] = []
    step_ids: set[str] = set()
    for index, item in enumerate(plan_raw):
        item = _require_mapping(item, path, f"agent_plan[{index}]")
        for key in ("id", "origin", "tool", "args"):
            if key not in item:
                _fail(path, f"agent_plan[{index}] missing '{key}'")
        if item["id"] in step_ids:
            _fail(path, f"duplicate step id '{item['id']}'")
        step_ids.add(item["id"])
        if item["origin"] not in ORIGINS:
            _fail(path, f"step '{item['id']}' has invalid origin")
        if item["tool"] not in TOOLS:
            _fail(path, f"step '{item['id']}' uses unknown tool '{item['tool']}'")
        if not isinstance(item["args"], dict):
            _fail(path, f"step '{item['id']}' args must be an object")
        plan.append(
            PlanStep(
                id=item["id"],
                origin=item["origin"],
                tool=item["tool"],
                args=item["args"],
                purpose=str(item.get("purpose", "")),
            )
        )

    expected = _require_mapping(raw["expected"], path, "expected")
    assertions = expected.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        _fail(path, "expected.assertions must be a non-empty list")
    seen_assertions: set[str] = set()
    for assertion in assertions:
        assertion = _require_mapping(assertion, path, "assertion")
        if not assertion.get("id") or not assertion.get("type"):
            _fail(path, "assertion requires id and type")
        if assertion["id"] in seen_assertions:
            _fail(path, f"duplicate assertion id '{assertion['id']}'")
        seen_assertions.add(assertion["id"])
        if assertion["type"] not in ASSERTION_TYPES:
            _fail(path, f"unknown assertion type '{assertion['type']}'")
        if assertion["type"] == "required_successful_calls":
            calls = assertion.get("calls")
            if not isinstance(calls, list) or not calls:
                _fail(path, f"assertion '{assertion['id']}' requires calls")
        if assertion["type"] in {"no_successful_call"}:
            if assertion.get("tool") not in TOOLS:
                _fail(path, f"assertion '{assertion['id']}' requires a known tool")
            if not isinstance(assertion.get("match", {}), dict):
                _fail(path, f"assertion '{assertion['id']}' match must be an object")

    for step in plan:
        for value in _walk_strings(step.args):
            for reference in TEMPLATE_RE.findall(value):
                if reference not in step_ids:
                    _fail(path, f"step '{step.id}' references unknown step '{reference}'")
                if plan.index(step) <= next(i for i, p in enumerate(plan) if p.id == reference):
                    _fail(path, f"step '{step.id}' references a later step '{reference}'")

    if raw["kind"] == "attack":
        if not expected.get("forbidden_behavior"):
            _fail(path, "attack expected.forbidden_behavior must be non-empty")
        if not any(step.origin == "injected" for step in plan) and raw["category"] == "indirect_prompt_injection":
            _fail(path, "prompt-injection cases require at least one injected-origin step")

    return TestCase(
        id=raw["id"],
        title=str(raw["title"]),
        kind=raw["kind"],
        category=raw["category"],
        severity=str(raw.get("severity", "medium")),
        task=str(raw["task"]),
        principal=principal,
        materials=materials,
        plan=plan,
        expected=expected,
        tags=[str(tag) for tag in raw.get("tags", [])],
        source_path=str(path),
        raw=raw,
    )


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def load_case(path: Path | str) -> TestCase:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CaseValidationError(f"{path}: cannot read case: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CaseValidationError(f"{path}: invalid JSON: {exc}") from exc
    raw = _require_mapping(raw, path, "case")
    return _parse_case(raw, path)


def load_cases(cases_dir: Path | str) -> list[TestCase]:
    cases_dir = Path(cases_dir)
    if not cases_dir.is_dir():
        raise CaseValidationError(f"{cases_dir}: cases directory does not exist")
    paths = sorted(cases_dir.rglob("*.json"))
    if not paths:
        raise CaseValidationError(f"{cases_dir}: no case JSON files found")
    cases = [load_case(path) for path in paths]
    seen: dict[str, str] = {}
    for case in cases:
        if case.id in seen:
            raise CaseValidationError(
                f"duplicate case id '{case.id}' in {seen[case.id]} and {case.source_path}"
            )
        seen[case.id] = case.source_path
    return cases


def validate_library(cases: list[TestCase]) -> dict[str, int]:
    """Validate that the library meets the documented minimum coverage."""

    counts: dict[str, int] = {
        "attack": 0,
        "benign": 0,
        "indirect_prompt_injection": 0,
        "secret_exfiltration": 0,
        "tool_overreach": 0,
    }
    for case in cases:
        counts[case.kind] += 1
        if case.kind == "attack":
            counts[case.category] += 1
    problems: list[str] = []
    for category in ATTACK_CATEGORIES:
        if counts[category] < 5:
            problems.append(f"category {category} has {counts[category]} attack cases; need >= 5")
    if counts["benign"] < 10:
        problems.append(f"library has {counts['benign']} benign cases; need >= 10")
    if problems:
        raise CaseValidationError("; ".join(problems))
    return counts
