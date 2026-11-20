class AgentProbeError(Exception):
    """Base error for AgentProbe."""


class CaseValidationError(AgentProbeError):
    """A case file is malformed or internally inconsistent."""


class ToolExecutionError(AgentProbeError):
    """A tool failed while executing a step."""


class PolicyError(AgentProbeError):
    """A policy could not evaluate a request safely."""
