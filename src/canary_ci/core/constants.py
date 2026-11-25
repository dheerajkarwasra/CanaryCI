"""Constants shared by configuration, trace recording, and policy checks."""

DEFAULT_SEED: str = "canary-default-seed-v1"

SENSITIVE_HOST_ENV_PREFIXES: tuple[str, ...] = (
    "OPENAI_",
    "ANTHROPIC_",
    "GEMINI_",
    "GOOGLE_",
    "AWS_",
    "AZURE_",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "CANARY_SIGNING_",
)

RESERVED_SYNTHETIC_DOMAINS: tuple[str, ...] = (
    ".invalid",
    ".example",
    ".test",
    ".corp.internal",
    "localhost",
    "127.0.0.1",
)

SEVERITY_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
