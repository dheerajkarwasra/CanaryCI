"""Replay deterministic synthetic tool fixtures and record their trace."""

import base64
import re
from collections.abc import Mapping
from typing import Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..canary.seeder import GeneratedCanary
from ..core.errors import ConfigurationError, ScenarioValidationError, UnknownCanaryReferenceError
from ..core.models import ScenarioSpec
from ..core.trace import TraceEventType, TraceWriter
from ..environments.base import CompositeEnvironment
from .base import AdapterSessionResult, AgentAdapter, SessionExecutionContext, TerminationReason

_MACRO = re.compile(
    r"\{\{(?:(base64|base64_offset1|hex|url|reverse|chunk1|chunk2):)?canary\.([^{}]+)\}\}"
)


class _ReplayCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class _ReplaySession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    calls: list[_ReplayCall] = Field(default_factory=list)
    final_response: str = ""


class ScriptedAgentAdapter(AgentAdapter):
    def __init__(
        self,
        mode: Literal["benign", "compromised"] = "benign",
        *,
        scenario: ScenarioSpec | None = None,
        canaries: Mapping[str, GeneratedCanary] | None = None,
    ) -> None:
        self._mode: Literal["benign", "compromised"] = mode
        self._scenario: ScenarioSpec | None = scenario
        self._canaries: dict[str, GeneratedCanary] = dict(canaries or {})

    def _render_text(self, text: str) -> str:
        def substitute(match: re.Match[str]) -> str:
            operator, canary_id = match.groups()
            canary = self._canaries.get(canary_id)
            if canary is None:
                raise UnknownCanaryReferenceError(f"Unknown canary reference: {canary_id}")
            value = canary.full_value
            match operator:
                case "base64":
                    return base64.b64encode(value.encode()).decode()
                case "base64_offset1":
                    return base64.b64encode(f'{{"k":"{value}"}}'.encode()).decode()
                case "hex":
                    return value.encode().hex()
                case "url":
                    return quote(value, safe="")
                case "reverse":
                    return value[::-1]
                case "chunk1":
                    return canary.core_token[:12]
                case "chunk2":
                    return canary.core_token[12:]
                case _:
                    return value

        return _MACRO.sub(substitute, text)

    def _render(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._render_text(value)
        if isinstance(value, list):
            return [self._render(item) for item in value]
        if isinstance(value, dict):
            return {key: self._render(item) for key, item in value.items()}
        return value

    def _session(self, session_id: str) -> _ReplaySession:
        if self._scenario is None:
            raise ConfigurationError("The scripted adapter requires a scenario")
        replay = self._scenario.scripted_replay
        if replay is None:
            return _ReplaySession(session_id=session_id)
        steps = replay.benign_steps if self._mode == "benign" else replay.compromised_steps
        calls: list[_ReplayCall] = []
        final = ""
        for item in steps:
            if item.get("session_id") != session_id:
                continue
            try:
                block = _ReplaySession.model_validate(item)
            except ValidationError as exc:
                raise ScenarioValidationError(
                    f"Invalid scripted replay block for {session_id}"
                ) from exc
            calls.extend(block.calls)
            final = block.final_response
        return _ReplaySession(session_id=session_id, calls=calls, final_response=final)

    async def run_session(
        self, ctx: SessionExecutionContext, env_dispatcher: CompositeEnvironment, trace: TraceWriter
    ) -> AdapterSessionResult:
        plan = self._session(ctx.session_id)
        event_count = len(trace.events)
        tools = {tool.name: tool for tool in env_dispatcher.list_tools()}
        if not any(
            event.event_type is TraceEventType.TOOLS_LISTED and event.session_id == ctx.session_id
            for event in trace.events[event_count:]
        ):
            trace.emit(
                TraceEventType.TOOLS_LISTED,
                "environment",
                ctx.session_id,
                0,
                payload={"tools": [tool.model_dump() for tool in tools.values()]},
            )
        calls = 0
        reason: TerminationReason = "completed"
        for step in plan.calls:
            if calls >= ctx.max_turns:
                reason = "max_turns"
                break
            if calls >= ctx.max_tool_calls:
                reason = "max_tool_calls"
                break
            arguments = self._render(step.args)
            schema = tools.get(step.tool)
            trace.emit(
                TraceEventType.TOOL_CALL,
                "agent",
                ctx.session_id,
                calls,
                step.tool,
                {
                    "arguments": arguments,
                    "is_sink": schema.is_sink if schema else False,
                    "trust_zone": schema.trust_zone if schema else "internal_trusted",
                },
            )
            result = await env_dispatcher.call_tool(step.tool, arguments, calls)
            trace.emit(
                TraceEventType.TOOL_RESPONSE,
                "environment",
                ctx.session_id,
                calls,
                step.tool,
                result.model_dump(),
            )
            calls += 1

        final = ""
        turns = calls
        if reason == "completed" and plan.final_response:
            if turns >= ctx.max_turns:
                reason = "max_turns"
            else:
                final = self._render_text(plan.final_response)
                trace.emit(
                    TraceEventType.AGENT_THOUGHT_OR_MESSAGE,
                    "agent",
                    ctx.session_id,
                    turns,
                    payload={"content": final},
                )
                turns += 1
        return AdapterSessionResult(
            prompt_tokens=0,
            completion_tokens=0,
            final_response=final,
            turns_used=turns,
            tool_calls_made=calls,
            terminated_reason=reason,
        )
