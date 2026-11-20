from __future__ import annotations

import base64
import re
from typing import Any

TEMPLATE_RE = re.compile(
    r"\{\{step:([A-Za-z0-9_-]+)\.output(?P<filters>(?:\s*\|\s*[a-zA-Z0-9:_-]+)*)\}\}"
)


class TemplateError(ValueError):
    pass


def _apply_filter(value: str, spec: str) -> str:
    parts = spec.strip().split(":")
    name = parts[0]
    if name == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if name == "slice":
        if len(parts) not in {2, 3}:
            raise TemplateError("slice filter expects slice:<start>:<end>")
        try:
            start = int(parts[1]) if parts[1] else 0
            end = int(parts[2]) if len(parts) == 3 and parts[2] else None
        except ValueError as exc:
            raise TemplateError("slice bounds must be integers") from exc
        return value[start:end]
    if name == "zero_width":
        return "​".join(value[index : index + 3] for index in range(0, len(value), 3))
    raise TemplateError(f"unknown template filter '{name}'")


def render_template(value: str, step_outputs: dict[str, str]) -> tuple[str, list[str]]:
    references: list[str] = []

    def replace(match: re.Match[str]) -> str:
        step_id = match.group(1)
        if step_id not in step_outputs:
            raise TemplateError(f"step '{step_id}' has no output")
        references.append(step_id)
        result = step_outputs[step_id]
        filters = match.group("filters") or ""
        for raw_filter in filters.split("|"):
            raw_filter = raw_filter.strip()
            if raw_filter:
                result = _apply_filter(result, raw_filter)
        return result

    return TEMPLATE_RE.sub(replace, value), references


def render_arguments(arguments: dict[str, Any], step_outputs: dict[str, str]) -> tuple[dict[str, Any], list[str]]:
    references: list[str] = []

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            rendered, refs = render_template(value, step_outputs)
            references.extend(refs)
            return rendered
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return value

    return walk(arguments), references
