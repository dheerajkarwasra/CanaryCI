"""Domain exceptions and their corresponding CLI exit codes."""


class CanaryCIError(Exception):
    """Base exception for user-facing CanaryCI failures."""

    exit_code: int = 2


class ConfigurationError(CanaryCIError):
    """Invalid project configuration or input artifact."""


class ScenarioValidationError(CanaryCIError):
    """Invalid scenario definition."""


class UnknownCanaryReferenceError(ScenarioValidationError):
    """A scenario refers to an undeclared canary."""


class ExpiredWaiverError(ConfigurationError):
    """A configuration waiver has expired."""


class MissingExtraError(ConfigurationError):
    """An optional dependency required by the configuration is unavailable."""


class AdapterExecutionError(CanaryCIError):
    """The target agent failed to execute or respond."""

    exit_code: int = 3


class AuditVerificationError(CanaryCIError):
    """An audit bundle failed verification."""

    exit_code: int = 1
