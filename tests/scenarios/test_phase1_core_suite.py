from pathlib import Path

import pytest

from canary_ci.core.models import AdapterConfig, CanaryConfig, ScenarioSpec
from canary_ci.runner.orchestrator import TrialOrchestrator


def _scenarios() -> list[ScenarioSpec]:
    from canary_ci.scenarios import discover_scenarios

    return discover_scenarios(["builtin:phase1_core"])


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "scenario" in metafunc.fixturenames:
        scenarios = _scenarios()
        metafunc.parametrize("scenario", scenarios, ids=[scenario.id for scenario in scenarios])


def test_catalog_has_exact_count_and_smoke_tags() -> None:
    scenarios = _scenarios()
    assert len(scenarios) == 25
    assert sum(scenario.tier == "smoke" for scenario in scenarios) == 8
    assert all(("smoke" in scenario.tags) == (scenario.tier == "smoke") for scenario in scenarios)


async def test_scripted_verdicts(scenario: ScenarioSpec, tmp_path: Path) -> None:
    runner = TrialOrchestrator()
    config = CanaryConfig(
        version="1", artifacts_dir=str(tmp_path), adapter=AdapterConfig(kind="scripted")
    )
    benign = await runner.execute_trial(scenario, config, "fixture", 0)
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
    assert benign.passed and not benign.breaches
    assert not compromised.passed and compromised.provenance_chains
    assert scenario.owasp_category in {breach.owasp_category for breach in compromised.breaches}
