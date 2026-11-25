from pathlib import Path

import pytest
from typer.testing import CliRunner

from canary_ci.adapters.base import AdapterSessionResult, SessionExecutionContext
from canary_ci.cli.app import app
from canary_ci.core.errors import ExpiredWaiverError
from canary_ci.core.models import AdapterConfig, CanaryConfig, WaiverSpec
from canary_ci.environments.base import CompositeEnvironment
from canary_ci.reporting.markdown_pr import load_json_summary, write_json_summary
from canary_ci.runner.orchestrator import TrialResult
from canary_ci.runner.suite_runner import ScenarioRunOutcome, SuiteRunSummary
from canary_ci.scenarios import discover_scenarios


def _counting_agent(
    ctx: SessionExecutionContext, env: CompositeEnvironment
) -> AdapterSessionResult:
    result = AdapterSessionResult(
        final_response="Done.", turns_used=1, tool_calls_made=0, terminated_reason="completed"
    )
    if ctx.session_id == "counted":
        return result.model_copy(update={"prompt_tokens": 0, "completion_tokens": 0})
    return result


async def test_trial_comparison_distinguishes_absent_usage_from_zero(tmp_path: Path) -> None:
    from canary_ci.runner.baseline_diff import compare_summaries, format_diff_markdown
    from canary_ci.runner.suite_runner import SuiteRunner

    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        adapter=AdapterConfig(kind="python", callable_path=f"{__name__}:_counting_agent"),
    )
    case = discover_scenarios(["builtin:all"])[0]
    counted = case.sessions[0].model_copy(update={"id": "counted"})
    unreported = case.sessions[0].model_copy(update={"id": "unreported"})
    before = await SuiteRunner().run([case.model_copy(update={"sessions": [counted]})], config)
    after = await SuiteRunner().run(
        [case.model_copy(update={"sessions": [unreported, counted]})], config
    )
    assert before.outcomes[0].trials[0].token_usage == {"prompt_tokens": 0, "completion_tokens": 0}
    assert after.outcomes[0].trials[0].token_usage == {}
    diff = compare_summaries(before, after)
    assert diff.entries[0].mean_token_delta is None
    assert "0.0 → —" in format_diff_markdown(diff)


def _summary(*scenarios: tuple[str, bool]) -> SuiteRunSummary:
    return SuiteRunSummary(
        run_id="fixture",
        outcomes=[
            ScenarioRunOutcome(
                scenario_id=name,
                owasp_category="ASI01",
                severity="high",
                trials=[
                    TrialResult(
                        run_id="fixture",
                        scenario_id=name,
                        trial_index=0,
                        passed=passed,
                        mitigated_by=None,
                        breaches=[],
                        provenance_chains=[],
                        trace_path=Path("fixture.trace.jsonl"),
                        duration_ms=0,
                        turns_used=0,
                        tool_calls_made=0,
                        token_usage={},
                    )
                ],
            )
            for name, passed in scenarios
        ],
    )


def test_baseline_statuses_and_cli_exit(tmp_path: Path) -> None:
    from canary_ci.runner.baseline_diff import DiffStatus, compare_summaries

    before = _summary(
        ("new", True), ("fixed", False), ("known", False), ("old", True), ("gone", True)
    )
    after = _summary(
        ("new", False), ("fixed", True), ("known", False), ("old", True), ("added", True)
    )
    comparison = compare_summaries(before, after)
    assert {entry.scenario_id: entry.status for entry in comparison.entries} == {
        "new": DiffStatus.NEW_REGRESSION,
        "fixed": DiffStatus.FIXED,
        "known": DiffStatus.KNOWN_FAIL,
        "old": DiffStatus.UNCHANGED_PASS,
        "added": DiffStatus.ADDED_PASS,
        "gone": DiffStatus.REMOVED,
    }
    left, right = tmp_path / "baseline.json", tmp_path / "current.json"
    write_json_summary(left, before)
    write_json_summary(right, after)
    runner = CliRunner()
    result = runner.invoke(app, ["diff", str(left), str(right), "--fail-on-regression"])
    assert result.exit_code == 1 and "NEW_REGRESSION" in result.output
    write_json_summary(right, before)
    assert (
        runner.invoke(app, ["diff", str(left), str(right), "--fail-on-regression"]).exit_code == 0
    )


def test_expired_waiver_prevents_validate_and_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canary_ci.runner.baseline_diff import validate_waivers

    monkeypatch.chdir(tmp_path)
    scenario = "asi01-email-hijack-external-forward"
    loaded = WaiverSpec.model_validate(
        {
            "scenario_id": scenario,
            "owner": "team@example.test",
            "reason": "Fixture waiver example",
            "expires_at": "2020-01-01",
        }
    )
    with pytest.raises(ExpiredWaiverError, match="team@example.test"):
        validate_waivers([loaded])
    config = """version: "1"
adapter: {kind: scripted, mode: compromised}
policy:
  waivers:
    - scenario_id: asi01-email-hijack-external-forward
      owner: team@example.test
      reason: Fixture waiver example
      expires_at: "2020-01-01"
"""
    Path("canary.yaml").write_text(config, encoding="utf-8")
    runner = CliRunner()
    assert runner.invoke(app, ["validate"]).exit_code == 2
    assert runner.invoke(app, ["run", "--scenario", scenario]).exit_code == 2
    Path("canary.yaml").write_text(config.replace("2020-01-01", "2099-01-01"), encoding="utf-8")
    active = runner.invoke(app, ["run", "--scenario", scenario, "--json-report", "run.json"])
    assert active.exit_code == 0 and "WAIVED" in active.output
    assert load_json_summary(Path("run.json")).outcomes[0].waived


def test_baseline_only_policy_ignores_known_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    Path("canary.yaml").write_text(
        """version: "1"
adapter: {kind: scripted, mode: compromised}
policy: {fail_on_new_regressions_only: true}
""",
        encoding="utf-8",
    )
    case = "asi01-email-hijack-external-forward"
    runner = CliRunner()
    assert (
        runner.invoke(app, ["run", "--scenario", case, "--json-report", "baseline.json"]).exit_code
        == 1
    )
    repeat = runner.invoke(app, ["run", "--scenario", case, "--baseline", "baseline.json"])
    assert repeat.exit_code == 0, repeat.output


def test_diff_rejects_an_expired_waiver_in_a_saved_report(tmp_path: Path) -> None:
    waiver = WaiverSpec.model_validate(
        {
            "scenario_id": "fixture",
            "owner": "team@example.test",
            "expires_at": "2020-01-01",
            "reason": "Fixture waiver example",
        }
    )
    baseline = _summary(("fixture", True))
    current = _summary(("fixture", False))
    current = current.model_copy(
        update={
            "outcomes": [
                current.outcomes[0].model_copy(
                    update={
                        "waived": True,
                        "waiver": waiver,
                    }
                )
            ]
        }
    )
    left, right = tmp_path / "baseline.json", tmp_path / "current.json"
    write_json_summary(left, baseline)
    write_json_summary(right, current)
    result = CliRunner().invoke(app, ["diff", str(left), str(right), "--fail-on-regression"])
    assert result.exit_code == 2 and "team@example.test" in result.output


def test_diff_reports_per_trial_performance_without_changing_policy(tmp_path: Path) -> None:
    import json

    baseline = _summary(("shared", True), ("removed", True))
    current = _summary(("shared", True), ("added", True))

    def measured(index: int, ms: int, prompt: int, completion: int) -> TrialResult:
        return (
            baseline.outcomes[0]
            .trials[0]
            .model_copy(
                update={
                    "trial_index": index,
                    "duration_ms": float(ms),
                    "token_usage": {"prompt_tokens": prompt, "completion_tokens": completion},
                }
            )
        )

    baseline.outcomes[0].trials[:] = [measured(0, 2, 2, 3), measured(1, 4, 4, 3)]
    current.outcomes[0].trials[:] = [measured(0, 12, 10, 6)]
    left, right, output = (tmp_path / name for name in ("left.json", "right.json", "diff.json"))
    write_json_summary(left, baseline)
    write_json_summary(right, current)
    result = CliRunner().invoke(
        app, ["diff", str(left), str(right), "--json-out", str(output), "--fail-on-regression"]
    )
    assert result.exit_code == 0, result.output
    entries = {entry["scenario_id"]: entry for entry in json.loads(output.read_text())["entries"]}
    shared = entries["shared"]
    assert shared["baseline_metrics"] == {
        "trial_count": 2,
        "mean_duration_ms": 3.0,
        "mean_tokens": 6.0,
    }
    assert shared["current_metrics"] == {
        "trial_count": 1,
        "mean_duration_ms": 12.0,
        "mean_tokens": 16.0,
    }
    assert shared["mean_duration_delta_ms"] == 9.0
    assert shared["mean_token_delta"] == 10.0
    assert "2 → 1" in result.output
    assert "3.0 → 12.0 (+9.0)" in result.output
    assert "6.0 → 16.0 (+10.0)" in result.output
    assert entries["added"]["baseline_metrics"] is None
    assert entries["removed"]["current_metrics"] is None
    assert entries["added"]["current_metrics"]["mean_tokens"] is None
    assert entries["added"]["mean_token_delta"] is None


def test_diff_reads_old_embedded_report_without_performance_fields() -> None:
    from canary_ci.runner.baseline_diff import BaselineDiffReport, format_diff_markdown

    report = BaselineDiffReport.model_validate(
        {
            "counts": {"UNCHANGED_PASS": 1},
            "entries": [
                {
                    "scenario_id": "fixture",
                    "status": "UNCHANGED_PASS",
                    "owasp_category": None,
                    "severity": None,
                    "baseline_breach_rate": 0.0,
                    "current_breach_rate": 0.0,
                }
            ],
            "has_new_regressions": False,
        }
    )
    assert report.entries[0].baseline_metrics is None
    assert "UNCHANGED_PASS" in format_diff_markdown(report)


@pytest.mark.parametrize("before_security,after_security", [(True, False), (False, True)])
def test_diff_gates_a_new_failure_in_an_independent_dimension(
    before_security: bool, after_security: bool
) -> None:
    from canary_ci.runner.baseline_diff import DiffStatus, compare_summaries

    before = _summary(("shared", before_security))
    after = _summary(("shared", after_security))
    before.outcomes[0].trials[0] = (
        before.outcomes[0].trials[0].model_copy(update={"task_completed": not before_security})
    )
    after.outcomes[0].trials[0] = (
        after.outcomes[0].trials[0].model_copy(update={"task_completed": not after_security})
    )
    report = compare_summaries(before, after)
    assert report.has_new_regressions
    assert report.entries[0].status is DiffStatus.NEW_REGRESSION
