import json
import os
import subprocess
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

import yaml

from canary_ci.core.models import (
    AdapterConfig,
    CanaryConfig,
    MockProfileSpec,
    ScenarioSpec,
    load_config_yaml,
    load_mock_profile_yaml,
    load_scenario_yaml,
)
from canary_ci.core.trace import TraceEventType, TraceReader
from canary_ci.runner.suite_runner import SuiteRunner, SuiteRunSummary
from canary_ci.scenarios import discover_scenarios

_ROOT = Path(__file__).resolve().parents[2]


def _shape(schema: dict[str, Any], document: dict[str, Any]) -> Any:
    if "$ref" in schema:
        return _shape(document["$defs"][schema["$ref"].split("/")[-1]], document)
    if "properties" in schema:
        return (
            frozenset(schema.get("required", ())),
            {key: _shape(value, document) for key, value in schema["properties"].items()},
        )
    if "items" in schema:
        return [_shape(schema["items"], document)]
    return None


def test_published_schema_fields_match_models_and_all_examples() -> None:
    for name, model in (
        ("config", CanaryConfig),
        ("scenario", ScenarioSpec),
        ("mock-profile", MockProfileSpec),
    ):
        schema = json.loads((_ROOT / "schemas" / f"{name}.schema.json").read_text())
        generated = model.model_json_schema()
        assert _shape(schema, schema) == _shape(generated, generated)
    for path in (_ROOT / "examples").rglob("*.yaml"):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if document.get("api_version") == "canary-ci/v1":
            load_scenario_yaml(path)
        elif document.get("api_version") == "canary-ci/mock-v1":
            load_mock_profile_yaml(path)
        else:
            load_config_yaml(path)
    assert len(discover_scenarios(["builtin:phase1_core"])) == 25


def _fingerprint(summary: SuiteRunSummary) -> list[tuple[Any, ...]]:
    signatures: list[tuple[Any, ...]] = []
    for outcome in summary.outcomes:
        trial = outcome.trials[0]
        events = TraceReader.read_jsonl(trial.trace_path)
        assert not Path(events[0].payload["sandbox_dir"]).exists()
        signatures.append(
            (
                outcome.scenario_id,
                [
                    event.payload["full_value"]
                    for event in events
                    if event.event_type is TraceEventType.CANARY_SEEDED
                ],
                [(breach.breach_kind, breach.transform_used) for breach in trial.breaches],
                [[node.stage for node in chain.nodes] for chain in trial.provenance_chains],
            )
        )
    return signatures


async def test_phase1_suites_are_isolated_deterministic_and_fast(tmp_path: Path) -> None:
    scenarios = discover_scenarios(["builtin:phase1_core"])
    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        concurrency=12,
        seed="fixed-seed-42",
        adapter=AdapterConfig(kind="scripted"),
    )
    runner = SuiteRunner()
    started = perf_counter()
    benign = await runner.run(scenarios, config)
    assert perf_counter() - started < 3.0
    assert len(benign.outcomes) == 25 and benign.passed
    _fingerprint(benign)
    compromised = config.model_copy(
        update={
            "adapter": AdapterConfig(kind="scripted", mode="compromised"),
        }
    )
    first = await runner.run(scenarios, compromised)
    second = await runner.run(scenarios, compromised)
    assert len(first.outcomes) == 25 and all(not outcome.passed for outcome in first.outcomes)
    assert _fingerprint(first) == _fingerprint(second)


def test_cli_subprocess_demo(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(_ROOT / "src")}
    env.pop("GITHUB_STEP_SUMMARY", None)
    base = [sys.executable, "-m", "canary_ci.cli.app"]
    init = subprocess.run(
        [*base, "init", "--demo"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert init.returncode == 0, init.stderr
    result = subprocess.run(
        [*base, "run", "--config", "canary.demo.yaml", "--json-report", "run.json"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    summary = SuiteRunSummary.model_validate_json((tmp_path / "run.json").read_bytes())
    assert len(summary.outcomes) == 8
    assert all(not outcome.passed for outcome in summary.outcomes)


async def test_shipped_examples_run_in_both_modes(tmp_path: Path) -> None:
    scenarios = discover_scenarios([str(_ROOT / "examples" / "scenarios")])
    assert scenarios
    config = CanaryConfig(
        version="1", artifacts_dir=str(tmp_path), adapter=AdapterConfig(kind="scripted")
    )
    benign = await SuiteRunner().run(scenarios, config)
    compromised = await SuiteRunner().run(
        scenarios,
        config.model_copy(
            update={
                "adapter": AdapterConfig(kind="scripted", mode="compromised"),
            }
        ),
    )
    assert all(outcome.passed for outcome in benign.outcomes)
    assert all(not outcome.passed for outcome in compromised.outcomes)
