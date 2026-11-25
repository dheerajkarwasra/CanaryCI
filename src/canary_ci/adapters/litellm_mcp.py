"""Run an async LiteLLM tool-calling session against a local test dispatcher."""

import json
from collections.abc import Awaitable, Callable
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import BaseModel

from ..core.errors import AdapterExecutionError, ConfigurationError, MissingExtraError
from ..core.models import AdapterConfig
from ..core.trace import TraceEventType, TraceWriter
from ..environments.base import ToolCallResult, ToolSchema
from .base import AdapterSessionResult, AgentAdapter, SessionExecutionContext, TerminationReason

type _CompletionFn = Callable[..., Awaitable[object]]


class _ToolDispatcher(Protocol):
    def list_tools(self) -> list[ToolSchema]: ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult: ...


def _load_completion(model: str) -> _CompletionFn:
    try:
        provider = import_module("litellm")
    except ModuleNotFoundError as exc:
        if exc.name != "litellm":
            raise
        raise MissingExtraError(
            "LiteLLM extra not installed. Run: uv pip install 'canary-ci[llm]'"
        ) from None
    completion = cast(_CompletionFn, provider.acompletion)
    lookup = getattr(provider, "get_supported_openai_params", None)
    supported = lookup(model=model) if callable(lookup) else None
    if supported is None:
        return completion
    unsupported_sampling = {"seed", "temperature"} - set(supported)

    async def invoke(**kwargs: Any) -> object:
        if kwargs.get("tools") and "tools" not in supported:
            raise AdapterExecutionError("The configured model does not support tool calling")
        if not kwargs.get("tools"):
            kwargs.pop("tools", None)
        for parameter in unsupported_sampling:
            kwargs.pop(parameter, None)
        return await completion(**kwargs)

    return invoke


def _response_object(value: object, *, exclude_unset: bool = False) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True, exclude_unset=exclude_unset)
    if isinstance(value, dict):
        return value
    raise AdapterExecutionError("LiteLLM returned an invalid completion")


def _token_count(usage: dict[str, Any], key: str) -> int:
    count = usage.get(key)
    if count is None:
        return 0
    if type(count) is not int or count < 0:
        raise AdapterExecutionError("LiteLLM returned an invalid token count")
    return count


def _parse_tool_call(value: object) -> tuple[str, str, dict[str, Any]]:
    call = _response_object(value)
    function = _response_object(call.get("function"))
    call_id, name, raw_arguments = call.get("id"), function.get("name"), function.get("arguments")
    if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not name:
        raise AdapterExecutionError("LiteLLM returned an invalid tool call")
    if not isinstance(raw_arguments, str):
        raise AdapterExecutionError("LiteLLM tool arguments must be a JSON object")
    try:
        arguments = json.loads(raw_arguments)
    except (ValueError, RecursionError):
        raise AdapterExecutionError("LiteLLM tool arguments must be a JSON object") from None
    if not isinstance(arguments, dict):
        raise AdapterExecutionError("LiteLLM tool arguments must be a JSON object")
    return call_id, name, arguments


class LiteLLMMcpAdapter(AgentAdapter):
    def __init__(self, config: AdapterConfig, completion_fn: _CompletionFn | None = None) -> None:
        if not config.model:
            raise ConfigurationError("The LiteLLM adapter requires a model")
        self._model: str = config.model
        self._system_prompt: str | None = config.system_prompt
        if self._system_prompt is None and config.system_prompt_file is not None:
            try:
                self._system_prompt = Path(config.system_prompt_file).read_text(encoding="utf-8")
            except (OSError, ValueError) as exc:
                raise ConfigurationError("Cannot read the LiteLLM system prompt file") from exc
        self._completion: _CompletionFn = (
            completion_fn if completion_fn is not None else _load_completion(self._model)
        )

    async def run_session(
        self, ctx: SessionExecutionContext, env_dispatcher: _ToolDispatcher, trace: TraceWriter
    ) -> AdapterSessionResult:
        messages: list[dict[str, Any]] = []
        system_prompt = "\n\n".join(
            prompt for prompt in (self._system_prompt, ctx.system_prompt_override) if prompt
        )
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": ctx.user_prompt})

        last_tools: list[dict[str, Any]] | None = None
        turns_used = tool_calls_made = prompt_tokens = completion_tokens = 0
        partial_usage = False
        final_response = ""
        reason: TerminationReason
        while turns_used < ctx.max_turns and tool_calls_made < ctx.max_tool_calls:
            turn = turns_used
            event_count = len(trace.events)
            schemas = env_dispatcher.list_tools()
            listed_tools = [tool.model_dump() for tool in schemas]
            if listed_tools != last_tools:
                if not any(
                    event.event_type is TraceEventType.TOOLS_LISTED
                    and event.session_id == ctx.session_id
                    for event in trace.events[event_count:]
                ):
                    trace.emit(
                        TraceEventType.TOOLS_LISTED,
                        "environment",
                        ctx.session_id,
                        turn,
                        payload={"tools": listed_tools},
                    )
                last_tools = listed_tools
            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema,
                    },
                }
                for tool in schemas
            ]
            try:
                reply = await self._completion(
                    model=self._model,
                    messages=messages,
                    tools=tools,
                    temperature=ctx.temperature,
                    seed=ctx.seed,
                    timeout=ctx.timeout_seconds,
                )
            except AdapterExecutionError:
                raise
            except Exception as exc:
                raise AdapterExecutionError("LiteLLM completion request failed") from exc

            response = _response_object(reply, exclude_unset=True)
            usage = response.get("usage")
            counts = _response_object(usage, exclude_unset=True) if usage is not None else {}
            if counts.get("prompt_tokens") is None or counts.get("completion_tokens") is None:
                partial_usage = True
            prompt_tokens += _token_count(counts, "prompt_tokens")
            completion_tokens += _token_count(counts, "completion_tokens")
            choices = response.get("choices")
            if not isinstance(choices, list) or not choices:
                raise AdapterExecutionError("LiteLLM completion returned no choices")
            message = _response_object(_response_object(choices[0]).get("message"))
            content = message.get("content")
            calls = message.get("tool_calls")
            if (content is not None and not isinstance(content, str)) or (
                calls is not None and not isinstance(calls, list)
            ):
                raise AdapterExecutionError("LiteLLM returned an invalid assistant message")
            turns_used += 1
            if content:
                trace.emit(
                    TraceEventType.AGENT_THOUGHT_OR_MESSAGE,
                    "agent",
                    ctx.session_id,
                    turn,
                    payload={"content": content},
                )
            if not calls:
                final_response = content or ""
                reason = "completed"
                break

            messages.append({**message, "role": "assistant"})
            by_name = {tool.name: tool for tool in schemas}
            for call in calls[: ctx.max_tool_calls - tool_calls_made]:
                call_id, name, arguments = _parse_tool_call(call)
                schema = by_name.get(name)
                trace.emit(
                    TraceEventType.TOOL_CALL,
                    "agent",
                    ctx.session_id,
                    turn,
                    name,
                    {
                        "arguments": arguments,
                        "is_sink": schema.is_sink if schema else False,
                        "trust_zone": schema.trust_zone if schema else "internal_trusted",
                    },
                )
                result = await env_dispatcher.call_tool(name, arguments, turn)
                trace.emit(
                    TraceEventType.TOOL_RESPONSE,
                    "environment",
                    ctx.session_id,
                    turn,
                    name,
                    result.model_dump(),
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": result.content,
                    }
                )
                tool_calls_made += 1
        else:
            reason = "max_tool_calls" if tool_calls_made >= ctx.max_tool_calls else "max_turns"

        return AdapterSessionResult(
            final_response=final_response,
            turns_used=turns_used,
            tool_calls_made=tool_calls_made,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            partial_token_usage=partial_usage,
            terminated_reason=reason,
        )
