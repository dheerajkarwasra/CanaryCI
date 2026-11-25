from pathlib import Path

import pytest

from canary_ci.core.models import AdapterConfig, CanaryConfig
from canary_ci.core.trace import TraceReader
from canary_ci.runner.orchestrator import TrialOrchestrator
from canary_ci.scenarios import discover_scenarios


@pytest.mark.parametrize("index", range(5))
async def test_phase2_persistence_verdicts(index: int, tmp_path: Path) -> None:
    scenarios = discover_scenarios(["builtin:phase2_persistence"])
    assert len(scenarios) == 5
    scenario = scenarios[index]
    config = CanaryConfig(
        version="1", artifacts_dir=str(tmp_path), adapter=AdapterConfig(kind="scripted")
    )
    runner = TrialOrchestrator()
    assert (await runner.execute_trial(scenario, config, "fixture", 0)).passed
    failed = await runner.execute_trial(
        scenario,
        config.model_copy(
            update={
                "adapter": AdapterConfig(kind="scripted", mode="compromised"),
            }
        ),
        "fixture",
        0,
    )
    assert not failed.passed
    events = TraceReader.read_jsonl(failed.trace_path)
    assert {events[breach.event_seq].session_id for breach in failed.breaches} == {
        "session_2_trigger"
    }
    assert any(
        breach.evidence.get("origin_session_id") == "session_1_ingest" for breach in failed.breaches
    )
