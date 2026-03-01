class ScanExecutionError(RuntimeError):
    """Raised when a collection fails safely."""


class AgentModeUnavailableError(RuntimeError):
    """Raised when agent mode is requested without a configured agent."""
