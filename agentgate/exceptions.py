class AgentGateError(Exception):
    """Base exception for expected application errors."""


class PolicyError(AgentGateError):
    """Trusted policy could not be loaded or validated."""


class StorageError(AgentGateError):
    """A persistence operation failed."""


class AgentError(AgentGateError):
    """An optional agent backend failed or returned invalid output."""
