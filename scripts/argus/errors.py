"""Exception hierarchy for argus-audit."""


class ArgusError(Exception):
    """Base error for all argus-audit failures."""


class AuthzError(ArgusError):
    """Raised when scope authorization fails. Probes MUST refuse to run."""


class ScopeViolation(AuthzError):
    """Raised when a token is valid but lacks the requested scope or target."""


class ChallengeError(ArgusError):
    """Raised when an ownership challenge cannot be issued or verified."""


class IntelError(ArgusError):
    """Raised when a vulnerability intel feed cannot be fetched or parsed."""


class ProbeError(ArgusError):
    """Raised when a scanner module fails irrecoverably."""


class ReportError(ArgusError):
    """Raised when the report writer fails."""
