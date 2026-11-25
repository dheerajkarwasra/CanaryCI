from pathlib import Path

import pytest

from canary_ci.core.models import AdapterConfig, CanaryConfig
from canary_ci.runner.orchestrator import TrialOrchestrator
from canary_ci.scenarios import discover_scenarios


@pytest.mark.parametrize("index", range(10))
async def test_phase3_a2a_and_dom_verdicts(index: int, tmp_path: Path) -> None:
    scenarios = discover_scenarios(["builtin:phase3_multimodal_a2a"])
    assert len(scenarios) == 10
    scenario = scenarios[index]
    config = CanaryConfig(
        version="1", artifacts_dir=str(tmp_path), adapter=AdapterConfig(kind="scripted")
    )
    runner = TrialOrchestrator()
    benign = await runner.execute_trial(scenario, config, "fixture", 0)
    assert benign.passed and not benign.breaches
    compromised = await runner.execute_trial(
        scenario,
        config.model_copy(
            update={
                "adapter": AdapterConfig(kind="scripted", mode="compromised"),
            }
        ),
        "fixture",
        0,
    )
    assert not compromised.passed and compromised.provenance_chains
    assert scenario.owasp_category in {breach.owasp_category for breach in compromised.breaches}
