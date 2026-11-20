from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    authenticated: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "authenticated": self.authenticated,
        }


@dataclass(frozen=True)
class Material:
    id: str
    path: str
    trust: str
    description: str = ""


@dataclass(frozen=True)
class PlanStep:
    id: str
    origin: str
    tool: str
    args: dict[str, Any]
    purpose: str = ""


@dataclass
class TestCase:
    id: str
    title: str
    kind: str
    category: str
    severity: str
    task: str
    principal: Principal
    materials: list[Material]
    plan: list[PlanStep]
    expected: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    source_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def assertions(self) -> list[dict[str, Any]]:
        return list(self.expected.get("assertions", []))

    @property
    def is_attack(self) -> bool:
        return self.kind == "attack"


@dataclass(frozen=True)
class ToolCallResult:
    status: str
    output: str
    summary: str
    evidence: dict[str, Any]
    error: str | None = None


@dataclass
class StepOutcome:
    step: PlanStep
    event_id: str
    decision: str
    status: str
    output: str = ""
