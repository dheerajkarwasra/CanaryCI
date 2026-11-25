"""Agent session contracts and subprocess environment sanitization."""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..core.constants import SENSITIVE_HOST_ENV_PREFIXES
from ..core.trace import TraceWriter
from ..environments.base import CompositeEnvironment

type TerminationReason = Literal[
    "completed", "max_turns", "max_tool_calls", "blocked_by_defense", "timeout", "error"
]


class SessionExecutionContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    run_id: str
    scenario_id: str
    trial_index: int
    session_id: str
    user_prompt: str
    system_prompt_override: str | None
    max_turns: int = Field(default=15, ge=0)
    max_tool_calls: int = Field(default=25, ge=0)
    timeout_seconds: float = Field(default=60.0, gt=0, allow_inf_nan=False)
    temperature: float = 0.0
    seed: int
    mcp_http_url: str | None = None
    mcp_stdio_cmd: list[str] | None = None
    a2a_endpoints: dict[str, str] = Field(default_factory=dict)
    browser_start_url: str | None = None


class AdapterSessionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    final_response: str
    turns_used: int = Field(ge=0)
    tool_calls_made: int = Field(ge=0)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    partial_token_usage: bool = False
    terminated_reason: TerminationReason
    error_message: str | None = None

    @property
    def has_complete_token_usage(self) -> bool:
        return (
            not self.partial_token_usage
            and {"prompt_tokens", "completion_tokens"} <= self.model_fields_set
        )


class AgentAdapter(ABC):
    @abstractmethod
    async def run_session(
        self, ctx: SessionExecutionContext, env_dispatcher: CompositeEnvironment, trace: TraceWriter
    ) -> AdapterSessionResult: ...


_SECRET_PREFIXES = tuple(prefix for prefix in SENSITIVE_HOST_ENV_PREFIXES if prefix.endswith("_"))
_RESTRICTED_ENV_NAMES = frozenset(SENSITIVE_HOST_ENV_PREFIXES) - frozenset(_SECRET_PREFIXES) | {
    "SSH_AUTH_SOCK",
    "KUBECONFIG",
    "DOCKER_HOST",
}


def sanitize_subprocess_env(
    base_env: Mapping[str, str], allowlist: Sequence[str]
) -> dict[str, str]:
    allowed = frozenset(allowlist)
    return {
        name: value
        for name, value in base_env.items()
        if name in allowed
        or (name not in _RESTRICTED_ENV_NAMES and not name.startswith(_SECRET_PREFIXES))
    }
