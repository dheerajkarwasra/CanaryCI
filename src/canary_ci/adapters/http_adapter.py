"""HTTP webhook transport for a configured agent session."""

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core.errors import AdapterExecutionError, ConfigurationError
from ..core.trace import TraceWriter
from ..environments.base import CompositeEnvironment
from .base import AdapterSessionResult, AgentAdapter, SessionExecutionContext


class _WebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    scenario_id: str
    session_id: str
    prompt: str
    mcp_sse_url: str | None
    a2a_endpoints: dict[str, str]
    max_turns: int


class _WebhookResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    final_response: str
    turns_used: int = Field(ge=0)
    tool_calls_made: int = Field(ge=0)


class HttpWebhookAdapter(AgentAdapter):
    def __init__(
        self, endpoint_url: str, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        try:
            url = httpx.URL(endpoint_url)
        except httpx.InvalidURL:
            raise ConfigurationError(
                "The HTTP adapter requires a valid HTTP or HTTPS endpoint"
            ) from None
        if url.scheme not in {"http", "https"} or not url.host:
            raise ConfigurationError("The HTTP adapter requires a valid HTTP or HTTPS endpoint")
        self._endpoint: httpx.URL = url
        self._transport: httpx.AsyncBaseTransport | None = transport

    async def run_session(
        self, ctx: SessionExecutionContext, env_dispatcher: CompositeEnvironment, trace: TraceWriter
    ) -> AdapterSessionResult:
        request = _WebhookRequest(
            run_id=ctx.run_id,
            scenario_id=ctx.scenario_id,
            session_id=ctx.session_id,
            prompt=ctx.user_prompt,
            mcp_sse_url=ctx.mcp_http_url,
            a2a_endpoints=ctx.a2a_endpoints,
            max_turns=ctx.max_turns,
        )
        try:
            async with httpx.AsyncClient(
                timeout=ctx.timeout_seconds, transport=self._transport, trust_env=False
            ) as client:
                response = await client.post(self._endpoint, json=request.model_dump(mode="json"))
                response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise AdapterExecutionError("The HTTP agent request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise AdapterExecutionError(
                f"The HTTP agent returned status {exc.response.status_code}"
            ) from exc
        except httpx.HTTPError as exc:
            raise AdapterExecutionError("The HTTP agent request failed") from exc

        try:
            result = _WebhookResponse.model_validate_json(response.content)
        except ValidationError:
            raise AdapterExecutionError(
                "The HTTP agent returned an invalid session result"
            ) from None
        return AdapterSessionResult(
            final_response=result.final_response,
            turns_used=result.turns_used,
            tool_calls_made=result.tool_calls_made,
            terminated_reason="completed",
        )
