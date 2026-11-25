"""Apply an explicitly configured security policy before simulated tool calls."""

import asyncio
import os
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from ..core.errors import ConfigurationError
from ..core.models import DefenseProxyConfig
from ..core.trace import TraceEventType, TraceWriter
from ..environments.base import CompositeEnvironment, ToolCallResult
from .base import sanitize_subprocess_env
from .cli_adapter import _stop


class _Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    allow: bool
    reason: str = ""
    modified_args: dict[str, Any] | None = None


class _PolicyCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str
    arguments: dict[str, Any]
    trust_zone: str
    is_sink: bool
    session_id: str
    turn_index: int


class DefenseProxyWrapper(CompositeEnvironment):
    def __init__(
        self,
        environment: CompositeEnvironment,
        config: DefenseProxyConfig,
        trace: TraceWriter,
        session_id: str,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__((environment,))
        self._config: DefenseProxyConfig = config
        self._trace: TraceWriter = trace
        self._session_id: str = session_id
        self._timeout: float = timeout
        self._transport: httpx.AsyncBaseTransport | None = transport
        self._endpoint: httpx.URL | None = None
        if config.kind == "webhook_policy":
            try:
                self._endpoint = httpx.URL(config.policy_url or "")
            except httpx.InvalidURL:
                raise ConfigurationError("Invalid defense policy URL") from None
            if self._endpoint.scheme not in {"http", "https"} or not self._endpoint.host:
                raise ConfigurationError("Defense policy URL must use HTTP or HTTPS")
        elif not config.command or not config.command[0]:
            raise ConfigurationError("Defense policy requires a nonempty command argv")

    async def _decide(self, call: _PolicyCall) -> _Decision:
        if self._endpoint is not None:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport, trust_env=False
            ) as client:
                response = await client.post(self._endpoint, json=call.model_dump(mode="json"))
                response.raise_for_status()
                return _Decision.model_validate_json(response.content)
        command = self._config.command or []
        process = await asyncio.create_subprocess_exec(  # noqa: S603 - Trusted policy argv.
            *command,
            env=sanitize_subprocess_env(os.environ, ()),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=os.name == "posix",
        )
        body = call.model_dump_json(include={"tool_name", "arguments"}).encode()
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(body), timeout=self._timeout)
        except (TimeoutError, asyncio.CancelledError):
            await _stop(process)
            raise
        if process.returncode != 0:
            raise ConfigurationError(f"Defense policy exited with status {process.returncode}")
        return _Decision.model_validate_json(stdout)

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        schema = self.tool_schema_for_call(name, arguments)
        call = _PolicyCall(
            tool_name=name,
            arguments=arguments,
            trust_zone=schema.trust_zone if schema else "internal_trusted",
            is_sink=schema.is_sink if schema else False,
            session_id=self._session_id,
            turn_index=turn_index,
        )
        attempt = next(
            (
                event
                for event in reversed(self._trace.events)
                if event.event_type is TraceEventType.TOOL_CALL
                and event.session_id == self._session_id
                and event.turn_index == turn_index
                and event.tool_name == name
            ),
            None,
        )
        try:
            async with asyncio.timeout(self._timeout):
                decision = await self._decide(call)
        except (
            TimeoutError,
            OSError,
            ValueError,
            ValidationError,
            httpx.HTTPError,
            ConfigurationError,
        ):
            decision = _Decision(allow=not self._config.fail_closed, reason="Policy request failed")
        payload: dict[str, Any] = {
            "action": "allowed" if decision.allow else "blocked",
            "reason": decision.reason,
            "call_event_seq": attempt.seq if attempt is not None else None,
        }
        if decision.allow and decision.modified_args is not None:
            arguments = decision.modified_args
            payload["effective_arguments"] = arguments
        self._trace.emit(
            TraceEventType.DEFENSE_DECISION,
            "defense_proxy",
            self._session_id,
            turn_index,
            name,
            payload,
        )
        if not decision.allow:
            return ToolCallResult(
                content=f"Blocked by security policy: {decision.reason}", is_error=True
            )
        return await super().call_tool(name, arguments, turn_index)
