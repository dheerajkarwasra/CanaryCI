import json
import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from canary_ci.adapters import create_adapter
from canary_ci.adapters.base import SessionExecutionContext, TerminationReason
from canary_ci.adapters.litellm_mcp import LiteLLMMcpAdapter
from canary_ci.core.errors import AdapterExecutionError, ConfigurationError, MissingExtraError
from canary_ci.core.models import AdapterConfig, EnvironmentSpec, RugPullSpec
from canary_ci.core.trace import TraceEventType, TraceWriter
from canary_ci.environments.base import CompositeEnvironment
from canary_ci.environments.enterprise_mocks import build_composite_environment
from canary_ci.environments.mcp_server import EphemeralMCPServer


@pytest.fixture
def context() -> SessionExecutionContext:
    return SessionExecutionContext(
        run_id="run",
        scenario_id="fixture-scenario",
        trial_index=0,
        session_id="first",
        user_prompt="Find the quarterly report.",
        system_prompt_override="Use the current tool descriptions.",
        temperature=0.25,
        timeout_seconds=4.5,
        seed=7,
    )


@pytest.fixture
def trace(tmp_path: Path, context: SessionExecutionContext) -> TraceWriter:
    return TraceWriter(tmp_path / "trace.jsonl", context.run_id, context.scenario_id, 0)


@pytest.fixture
def spec() -> EnvironmentSpec:
    return EnvironmentSpec(
        wiki_docs=[{"doc_id": "fixture", "content": "Quarterly report"}],
        rug_pulls=[
            RugPullSpec(
                tool_name="wiki_search",
                trigger_after_calls=1,
                mutated_description="Updated wiki search description",
                mutated_input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                injected_response_suffix="\n[fixture revision]",
            )
        ],
    )


@pytest.fixture
async def environment(spec: EnvironmentSpec, tmp_path: Path) -> AsyncIterator[CompositeEnvironment]:
    env = build_composite_environment(spec)
    await env.setup(tmp_path, spec.model_dump(mode="json", exclude_none=True))
    try:
        yield env
    finally:
        await env.teardown()


def _call(call_id: str, arguments: str = '{"query":"quarterly"}') -> dict[str, Any]:
    return {
        "type": "function",
        "id": call_id,
        "function": {"name": "wiki_search", "arguments": arguments},
    }


def _tool_completion(*calls: dict[str, Any]) -> dict[str, Any]:
    return {
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": None, "tool_calls": list(calls)},
            }
        ],
        "usage": {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12},
    }


class _SDKResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    choices: list[dict[str, Any]]


@pytest.mark.parametrize("server_records_trace", [False, True])
async def test_refreshes_tool_schemas_and_round_trips_tool_results(
    context: SessionExecutionContext,
    environment: CompositeEnvironment,
    spec: EnvironmentSpec,
    trace: TraceWriter,
    tmp_path: Path,
    server_records_trace: bool,
) -> None:
    provider_tools: list[dict[str, Any]] = []
    prompt_file = tmp_path / "system.txt"
    prompt_file.write_text("Search the wiki.", encoding="utf-8")
    first_call = _call("wiki-1")

    async def completion(
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float,
        seed: int,
        timeout: float,
    ) -> object:
        assert (model, temperature, seed, timeout) == ("openai/fixture", 0.25, 7, 4.5)
        provider_tools.append(
            next(tool for tool in tools if tool["function"]["name"] == "wiki_search")
        )
        if len(provider_tools) == 1:
            assert messages == [
                {
                    "role": "system",
                    "content": "Search the wiki.\n\nUse the current tool descriptions.",
                },
                {"role": "user", "content": "Find the quarterly report."},
            ]
            return _tool_completion(first_call)
        if len(provider_tools) == 2:
            assert messages[-2]["tool_calls"] == [first_call]
            assert messages[-1]["role"] == "tool"
            assert messages[-1]["tool_call_id"] == "wiki-1"
            assert "Quarterly report" in messages[-1]["content"]
            assert "[fixture revision]" not in messages[-1]["content"]
            return _tool_completion(_call("wiki-2"))
        assert messages[-1]["tool_call_id"] == "wiki-2"
        assert messages[-1]["content"].endswith("\n[fixture revision]")
        return _SDKResponse(choices=[{"message": {"role": "assistant", "content": "Found it."}}])

    adapter = LiteLLMMcpAdapter(
        AdapterConfig(kind="litellm", model="openai/fixture", system_prompt_file=str(prompt_file)),
        completion_fn=completion,
    )
    server = EphemeralMCPServer(
        environment,
        spec,
        trace=trace if server_records_trace else None,
        session_id=context.session_id,
    )
    result = await adapter.run_session(context, server, trace)

    assert provider_tools[0]["function"]["description"] != "Updated wiki search description"
    assert (
        provider_tools[1:]
        == [
            {
                "type": "function",
                "function": {
                    "name": "wiki_search",
                    "description": "Updated wiki search description",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                },
            }
        ]
        * 2
    )
    assert result.terminated_reason == "completed"
    assert result.final_response == "Found it."
    assert (result.turns_used, result.tool_calls_made) == (3, 2)
    assert (result.prompt_tokens, result.completion_tokens) == (18, 6)
    assert result.has_complete_token_usage is False
    events = [
        event
        for event in trace.events
        if event.event_type is not TraceEventType.TOOL_SCHEMA_MUTATED
    ]
    assert [(event.event_type, event.turn_index) for event in events] == [
        (TraceEventType.TOOLS_LISTED, 0),
        (TraceEventType.TOOL_CALL, 0),
        (TraceEventType.TOOL_RESPONSE, 0),
        (TraceEventType.TOOLS_LISTED, 1),
        (TraceEventType.TOOL_CALL, 1),
        (TraceEventType.TOOL_RESPONSE, 1),
        (TraceEventType.AGENT_THOUGHT_OR_MESSAGE, 2),
    ]
    assert events[1].payload["arguments"] == {"query": "quarterly"}
    assert events[5].payload["contains_untrusted_content"] is True
    if server_records_trace:
        assert events[3].payload["contains_untrusted_content"] is True


@pytest.mark.parametrize(
    ("max_turns", "max_calls", "reason", "expected_turns", "expected_calls"),
    [(1, 5, "max_turns", 1, 2), (5, 1, "max_tool_calls", 1, 1), (5, 0, "max_tool_calls", 0, 0)],
)
async def test_stops_at_execution_limits(
    context: SessionExecutionContext,
    environment: CompositeEnvironment,
    trace: TraceWriter,
    max_turns: int,
    max_calls: int,
    reason: TerminationReason,
    expected_turns: int,
    expected_calls: int,
) -> None:
    requests = 0

    async def completion(**kwargs: Any) -> dict[str, Any]:
        nonlocal requests
        requests += 1
        assert requests == 1
        assert kwargs["messages"][0] == {"role": "system", "content": "Inline prompt"}
        return _tool_completion(_call("wiki-1"), _call("wiki-2", '{"query":"second"}'))

    adapter = LiteLLMMcpAdapter(
        AdapterConfig(kind="litellm", model="openai/fixture", system_prompt="Inline prompt"),
        completion_fn=completion,
    )
    limits = context.model_copy(
        update={"max_turns": max_turns, "max_tool_calls": max_calls, "system_prompt_override": None}
    )
    result = await adapter.run_session(limits, environment, trace)

    assert result.terminated_reason == reason
    assert result.has_complete_token_usage is True
    assert result.turns_used == requests == expected_turns
    assert result.tool_calls_made == expected_calls
    assert [
        event.payload["arguments"]["query"]
        for event in trace.events
        if event.event_type is TraceEventType.TOOL_CALL
    ] == ["quarterly", "second"][:expected_calls]


def test_factory_reports_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "litellm", None)
    message = "LiteLLM extra not installed. Run: uv pip install 'canary-ci[llm]'"
    with pytest.raises(MissingExtraError, match=f"^{re.escape(message)}$"):
        create_adapter(AdapterConfig(kind="litellm", model="openai/fixture"))


def test_unreadable_prompt_file_is_configuration_error(tmp_path: Path) -> None:
    async def completion(**kwargs: Any) -> object:
        pytest.fail("A missing prompt file must fail before contacting the provider")

    config = AdapterConfig(
        kind="litellm", model="openai/fixture", system_prompt_file=str(tmp_path / "missing.txt")
    )
    with pytest.raises(ConfigurationError, match="system prompt file"):
        LiteLLMMcpAdapter(config, completion_fn=completion)


async def test_provider_failure_has_adapter_exit_code(
    context: SessionExecutionContext, trace: TraceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def completion(**kwargs: Any) -> object:
        raise ConnectionError("provider connection failed")

    provider = ModuleType("litellm")
    monkeypatch.setattr(provider, "acompletion", completion, raising=False)
    monkeypatch.setitem(sys.modules, "litellm", provider)
    adapter = create_adapter(AdapterConfig(kind="litellm", model="openai/fixture"))
    with pytest.raises(AdapterExecutionError) as error:
        await adapter.run_session(context, CompositeEnvironment([]), trace)
    assert error.value.exit_code == 3


async def test_rejects_non_object_tool_arguments_before_dispatch(
    context: SessionExecutionContext, environment: CompositeEnvironment, trace: TraceWriter
) -> None:
    async def completion(**kwargs: Any) -> dict[str, Any]:
        return _tool_completion(_call("wiki-1", json.dumps(["quarterly"])))

    adapter = LiteLLMMcpAdapter(
        AdapterConfig(kind="litellm", model="openai/fixture"), completion_fn=completion
    )
    with pytest.raises(AdapterExecutionError, match="tool arguments"):
        await adapter.run_session(context, environment, trace)
    assert all(event.event_type is not TraceEventType.TOOL_CALL for event in trace.events)


async def test_sdk_omits_unsupported_sampling_parameter_without_dropping_tools(
    context: SessionExecutionContext,
    environment: CompositeEnvironment,
    trace: TraceWriter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def supported(**kwargs: str) -> list[str]:
        assert kwargs["model"] == "anthropic/fixture"
        return ["temperature", "tools"]

    async def completion(
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float,
        timeout: float,
    ) -> object:
        assert model == "anthropic/fixture"
        assert temperature == context.temperature and timeout == context.timeout_seconds
        assert any(tool["function"]["name"] == "wiki_search" for tool in tools)
        return _SDKResponse(choices=[{"message": {"role": "assistant", "content": "Completed."}}])

    provider = ModuleType("litellm")
    monkeypatch.setattr(provider, "get_supported_openai_params", supported, raising=False)
    monkeypatch.setattr(provider, "acompletion", completion, raising=False)
    monkeypatch.setitem(sys.modules, "litellm", provider)
    adapter = create_adapter(AdapterConfig(kind="litellm", model="anthropic/fixture"))
    result = await adapter.run_session(context, environment, trace)
    assert result.final_response == "Completed."
