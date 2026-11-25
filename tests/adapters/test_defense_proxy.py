import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

from canary_ci.core.models import AdapterConfig, CanaryConfig, DefenseProxyConfig
from canary_ci.core.trace import TraceEventType, TraceReader
from canary_ci.runner.orchestrator import TrialOrchestrator
from canary_ci.runner.suite_runner import replay_trace_file
from canary_ci.scenarios import discover_scenarios


async def test_webhook_blocks_synthetic_sink_and_replay_stays_clean(tmp_path: Path) -> None:
    scenario = next(
        scenario
        for scenario in discover_scenarios(["builtin:phase1_core"])
        if scenario.id == "asi02-pr-diff-env-base64-exfil"
    )
    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        adapter=AdapterConfig(kind="scripted", mode="compromised"),
    )
    assert not (await TrialOrchestrator().execute_trial(scenario, config, "fixture", 0)).passed

    def policy(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["session_id"] == "first"
        assert body["is_sink"] is (body["tool_name"] == "git_post_pr_comment")
        blocked = body["trust_zone"] == "external_untrusted" and "diag_ref=" in body[
            "arguments"
        ].get("body", "")
        return httpx.Response(200, json={"allow": not blocked, "reason": "Fixture policy"})

    runner = TrialOrchestrator(policy_transport=httpx.MockTransport(policy))
    settings = config.model_copy(
        update={
            "defense_proxy": DefenseProxyConfig(
                kind="webhook_policy",
                policy_url="https://policy.example/check",
            )
        }
    )
    result = await runner.execute_trial(scenario, settings, "fixture", 0)
    assert result.passed and result.mitigated_by == "defense_proxy"
    blocked = [
        event
        for event in TraceReader.read_jsonl(result.trace_path)
        if event.event_type is TraceEventType.DEFENSE_DECISION
        and event.payload["action"] == "blocked"
    ]
    assert [event.tool_name for event in blocked] == ["git_post_pr_comment"]
    assert replay_trace_file(result.trace_path, reverify=True).passed


async def test_command_policy_receives_call_and_blocks(tmp_path: Path) -> None:
    scenario = next(
        scenario
        for scenario in discover_scenarios(["builtin:phase1_core"])
        if scenario.id == "asi01-email-hijack-external-forward"
    )
    script = (
        "import sys,json; call=json.load(sys.stdin); "
        'print(json.dumps({"allow":call["tool_name"]!="email_send_message"}))'
    )
    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        adapter=AdapterConfig(kind="scripted", mode="compromised"),
        defense_proxy=DefenseProxyConfig(
            kind="mcp_command_wrapper", command=[sys.executable, "-c", script]
        ),
    )
    result = await TrialOrchestrator().execute_trial(scenario, config, "fixture", 0)
    assert result.passed and result.mitigated_by == "defense_proxy"


@pytest.mark.parametrize(
    ("case_id", "sink"),
    [
        ("asi01-email-hijack-external-forward", "email_send_message"),
        ("asi07-a2a-spoofed-agent-card-exfil", "a2a_delegate_task"),
    ],
)
async def test_policy_sees_recipient_specific_sink_metadata(
    tmp_path: Path,
    case_id: str,
    sink: str,
) -> None:
    scenario = next(case for case in discover_scenarios(["builtin:all"]) if case.id == case_id)
    observed: list[tuple[bool, str]] = []

    def policy(request: httpx.Request) -> httpx.Response:
        call = json.loads(request.content)
        if call["tool_name"] == sink:
            observed.append((call["is_sink"], call["trust_zone"]))
        return httpx.Response(200, json={"allow": call["trust_zone"] != "external_untrusted"})

    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        adapter=AdapterConfig(kind="scripted", mode="compromised"),
        defense_proxy=DefenseProxyConfig(
            kind="webhook_policy", policy_url="https://policy.example/check"
        ),
    )
    runner = TrialOrchestrator(policy_transport=httpx.MockTransport(policy))
    result = await runner.execute_trial(scenario, config, "fixture", 0)
    assert observed == [(True, "external_untrusted")]
    assert result.passed and result.mitigated_by == "defense_proxy"


async def test_policy_timeout_blocks_before_agent_session_deadline(tmp_path: Path) -> None:
    scenario = next(
        case
        for case in discover_scenarios(["builtin:phase1_core"])
        if case.id == "asi01-email-hijack-external-forward"
    )
    pending = asyncio.Event()

    async def policy(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content)["is_sink"]:
            await pending.wait()
        return httpx.Response(200, json={"allow": True})

    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        adapter=AdapterConfig(kind="scripted", mode="compromised", timeout_seconds=1),
        defense_proxy=DefenseProxyConfig(
            kind="webhook_policy", policy_url="https://policy.example/check"
        ),
    )
    result = await TrialOrchestrator(policy_transport=httpx.MockTransport(policy)).execute_trial(
        scenario,
        config,
        "fixture",
        0,
    )
    assert result.passed and result.mitigated_by == "defense_proxy"
    assert replay_trace_file(result.trace_path, reverify=True).passed
