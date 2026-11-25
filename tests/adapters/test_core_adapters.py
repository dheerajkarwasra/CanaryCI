import base64
import json
import sys
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import httpx
import pytest

from canary_ci.adapters import create_adapter
from canary_ci.adapters.base import SessionExecutionContext, sanitize_subprocess_env
from canary_ci.canary.seeder import CanarySeeder
from canary_ci.core.errors import AdapterExecutionError, UnknownCanaryReferenceError
from canary_ci.core.models import AdapterConfig, CanarySpec, ScenarioSpec
from canary_ci.core.trace import TraceEventType, TraceWriter
from canary_ci.environments.base import CompositeEnvironment
from canary_ci.environments.workspace_fs import WorkspaceFSEnvironment


def _context() -> SessionExecutionContext:
    return SessionExecutionContext(
        run_id="run",
        scenario_id="fixture-scenario",
        trial_index=0,
        session_id="first",
        user_prompt="Process the fixture.",
        system_prompt_override=None,
        seed=7,
        mcp_http_url="http://127.0.0.1:43210/sse",
        a2a_endpoints={"fixture": "http://127.0.0.1:43211"},
        browser_start_url="http://127.0.0.1:43212/start",
    )


def _trace(tmp_path: Path) -> TraceWriter:
    return TraceWriter(tmp_path / "trace.jsonl", "run", "fixture-scenario", 0)


def _scenario(content: str) -> ScenarioSpec:
    return ScenarioSpec.model_validate(
        {
            "api_version": "canary-ci/v1",
            "id": "fixture-scenario",
            "title": "Fixture scenario",
            "owasp_category": "ASI02",
            "severity": "high",
            "assertions": {},
            "sessions": [{"id": "first", "user_prompt": "Process the fixture."}],
            "scripted_replay": {
                "benign_steps": [
                    {"session_id": "first", "calls": [], "final_response": "Benign fixture"}
                ],
                "compromised_steps": [
                    {"session_id": "second", "calls": [], "final_response": "Other session"},
                    {
                        "session_id": "first",
                        "calls": [
                            {
                                "tool": "fs_write_file",
                                "args": {"path": "test.txt", "content": content},
                            },
                            {"tool": "fs_read_file", "args": {"path": "test.txt"}},
                        ],
                        "final_response": content,
                    },
                ],
            },
        }
    )


def test_sanitize_subprocess_env_preserves_only_allowed_sensitive_values() -> None:
    source = {
        "PATH": "/bin",
        "AWS_SECRET_ACCESS_KEY": "fixture-a",
        "GITHUB_TOKEN": "fixture-b",
        "OPENAI_API_KEY": "fixture-c",
        "ANTHROPIC_API_KEY": "fixture-d",
        "GEMINI_API_KEY": "fixture-e",
        "GOOGLE_API_KEY": "fixture-f",
        "AZURE_KEY": "fixture-g",
        "GH_TOKEN": "fixture-h",
        "SSH_AUTH_SOCK": "fixture-i",
        "KUBECONFIG": "fixture-j",
        "DOCKER_HOST": "fixture-k",
        "CANARY_SIGNING_KEY": "fixture-l",
        "FIXTURE": "ordinary",
    }

    assert sanitize_subprocess_env(source, ["OPENAI_API_KEY", "AWS_", "MISSING"]) == {
        "PATH": "/bin",
        "OPENAI_API_KEY": "fixture-c",
        "FIXTURE": "ordinary",
    }
    assert source["AWS_SECRET_ACCESS_KEY"] == "fixture-a"


async def test_scripted_replay_resolves_macros_and_records_trace(tmp_path: Path) -> None:
    names = ("", "base64:", "base64_offset1:", "hex:", "url:", "reverse:", "chunk1:", "chunk2:")
    scenario = _scenario("|".join("{{" + prefix + "canary.fixture}}" for prefix in names))
    spec = CanarySpec.model_validate(
        {"id": "fixture", "kind": "data", "format_preset": "pii_ssn_tagged"}
    )
    canaries = CanarySeeder.generate_all([spec], "seed", scenario.id, 0)
    canary = canaries["fixture"]
    full = canary.full_value
    expected = "|".join(
        (
            full,
            base64.b64encode(full.encode()).decode(),
            base64.b64encode(f'{{"k":"{full}"}}'.encode()).decode(),
            full.encode().hex(),
            quote(full, safe=""),
            full[::-1],
            canary.core_token[:12],
            canary.core_token[12:],
        )
    )
    dispatcher = CompositeEnvironment([WorkspaceFSEnvironment()])
    await dispatcher.setup(tmp_path, {})
    trace = _trace(tmp_path)
    adapter = create_adapter(
        AdapterConfig(kind="scripted", mode="compromised"), scenario=scenario, canaries=canaries
    )

    result = await adapter.run_session(_context(), dispatcher, trace)

    assert result.final_response == expected
    assert result.terminated_reason == "completed"
    assert (result.turns_used, result.tool_calls_made) == (3, 2)
    assert [event.event_type for event in trace.events] == [
        TraceEventType.TOOLS_LISTED,
        TraceEventType.TOOL_CALL,
        TraceEventType.TOOL_RESPONSE,
        TraceEventType.TOOL_CALL,
        TraceEventType.TOOL_RESPONSE,
        TraceEventType.AGENT_THOUGHT_OR_MESSAGE,
    ]
    assert trace.events[1].payload["arguments"]["content"] == expected
    assert trace.events[4].payload["content"] == expected
    assert trace.events[-1].payload["content"] == expected
    await dispatcher.teardown()


@pytest.mark.parametrize("limit", ["max_turns", "max_tool_calls"])
async def test_scripted_replay_stops_at_context_limits(
    tmp_path: Path, limit: Literal["max_turns", "max_tool_calls"]
) -> None:
    dispatcher = CompositeEnvironment([WorkspaceFSEnvironment()])
    await dispatcher.setup(tmp_path, {})
    trace = _trace(tmp_path)
    adapter = create_adapter(
        AdapterConfig(kind="scripted", mode="compromised"), scenario=_scenario("Fixture")
    )

    result = await adapter.run_session(_context().model_copy(update={limit: 1}), dispatcher, trace)

    assert result.terminated_reason == limit
    assert result.tool_calls_made == 1
    assert result.final_response == ""
    assert [
        event.tool_name for event in trace.events if event.event_type is TraceEventType.TOOL_CALL
    ] == ["fs_write_file"]
    await dispatcher.teardown()


async def test_scripted_replay_selects_benign_mode_and_validates_references(tmp_path: Path) -> None:
    scenario = _scenario("{{reverse:canary.missing}}")
    dispatcher = CompositeEnvironment([WorkspaceFSEnvironment()])
    await dispatcher.setup(tmp_path, {})
    trace = _trace(tmp_path)
    benign = create_adapter(AdapterConfig(kind="scripted"), scenario=scenario)
    compromised = create_adapter(
        AdapterConfig(kind="scripted", mode="compromised"), scenario=scenario
    )

    result = await benign.run_session(_context(), dispatcher, trace)
    assert result.final_response == "Benign fixture" and result.tool_calls_made == 0
    with pytest.raises(UnknownCanaryReferenceError, match="missing"):
        await compromised.run_session(_context(), dispatcher, trace)

    assert not (tmp_path / "workspace" / "test.txt").exists()
    await dispatcher.teardown()


async def test_cli_passes_context_and_sanitizes_actual_child_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fixture-aws")
    monkeypatch.setenv("GITHUB_TOKEN", "fixture-git")
    command = [
        sys.executable,
        "-c",
        """
import json
import os
keys = ('CANARY_PROMPT', 'CANARY_SESSION_ID', 'CANARY_MCP_SSE_URL',
        'CANARY_A2A_ENDPOINTS_JSON', 'CANARY_BROWSER_START_URL',
        'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN')
print(json.dumps({key: os.getenv(key) for key in keys}))
""",
    ]
    adapter = create_adapter(AdapterConfig(kind="cli", command=command, pass_env=["GITHUB_TOKEN"]))

    result = await adapter.run_session(_context(), CompositeEnvironment([]), _trace(tmp_path))

    assert result.terminated_reason == "completed"
    actual = json.loads(result.final_response)
    assert actual == {
        "CANARY_PROMPT": "Process the fixture.",
        "CANARY_SESSION_ID": "first",
        "CANARY_MCP_SSE_URL": "http://127.0.0.1:43210/sse",
        "CANARY_A2A_ENDPOINTS_JSON": '{"fixture": "http://127.0.0.1:43211"}',
        "CANARY_BROWSER_START_URL": "http://127.0.0.1:43212/start",
        "AWS_SECRET_ACCESS_KEY": None,
        "GITHUB_TOKEN": "fixture-git",
    }


async def test_cli_timeout_and_nonzero_exit(tmp_path: Path) -> None:
    dispatcher = CompositeEnvironment([])
    trace = _trace(tmp_path)
    stalled = create_adapter(
        AdapterConfig(kind="cli", command=[sys.executable, "-c", "import time; time.sleep(20)"])
    )
    failed = create_adapter(
        AdapterConfig(kind="cli", command=[sys.executable, "-c", "raise SystemExit(4)"])
    )

    result = await stalled.run_session(
        _context().model_copy(update={"timeout_seconds": 0.1}), dispatcher, trace
    )

    assert result.terminated_reason == "timeout"
    with pytest.raises(AdapterExecutionError, match="status 4"):
        await failed.run_session(_context(), dispatcher, trace)


async def test_http_adapter_posts_wire_contract(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://agent.invalid/run"
        assert json.loads(request.content) == {
            "run_id": "run",
            "scenario_id": "fixture-scenario",
            "session_id": "first",
            "prompt": "Process the fixture.",
            "mcp_sse_url": "http://127.0.0.1:43210/sse",
            "a2a_endpoints": {"fixture": "http://127.0.0.1:43211"},
            "max_turns": 15,
        }
        return httpx.Response(
            200, json={"final_response": "Fixture response", "turns_used": 2, "tool_calls_made": 1}
        )

    adapter = create_adapter(
        AdapterConfig(kind="http", endpoint_url="https://agent.invalid/run"),
        http_transport=httpx.MockTransport(respond),
    )
    result = await adapter.run_session(_context(), CompositeEnvironment([]), _trace(tmp_path))

    assert (result.final_response, result.turns_used, result.tool_calls_made) == (
        "Fixture response",
        2,
        1,
    )


@pytest.mark.parametrize("entrypoint", ["async_agent", "sync_agent"])
async def test_python_adapter_calls_imported_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entrypoint: str
) -> None:
    module = "core_adapter_fixture"
    (tmp_path / f"{module}.py").write_text(
        """
from canary_ci.adapters.base import AdapterSessionResult, SessionExecutionContext
from canary_ci.environments.base import CompositeEnvironment

def sync_agent(
    ctx: SessionExecutionContext, dispatcher: CompositeEnvironment,
) -> AdapterSessionResult:
    return AdapterSessionResult(final_response=ctx.user_prompt, turns_used=1,
                                tool_calls_made=0, terminated_reason='completed')

async def async_agent(
    ctx: SessionExecutionContext, dispatcher: CompositeEnvironment,
) -> AdapterSessionResult:
    return sync_agent(ctx, dispatcher)
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, module, raising=False)
    adapter = create_adapter(AdapterConfig(kind="python", callable_path=f"{module}:{entrypoint}"))

    result = await adapter.run_session(_context(), CompositeEnvironment([]), _trace(tmp_path))

    assert result.final_response == "Process the fixture."
    assert result.terminated_reason == "completed"
