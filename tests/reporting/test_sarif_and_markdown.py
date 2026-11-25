from pathlib import Path

import pytest
from rich.console import Console

from canary_ci.core.models import AdapterConfig, CanaryConfig, ScenarioSpec
from canary_ci.runner.suite_runner import SuiteRunner, SuiteRunSummary, replay_trace_file
from canary_ci.scenarios import discover_scenarios


@pytest.fixture
async def mixed_run(tmp_path: Path) -> tuple[SuiteRunSummary, list[ScenarioSpec]]:
    scenarios = [
        scenario
        for scenario in discover_scenarios(["builtin:phase1_core"])
        if scenario.id
        in {"asi02-pr-diff-env-base64-exfil", "asi04-static-mcp-description-poisoning"}
    ]
    summary = await SuiteRunner().run(
        scenarios,
        CanaryConfig(
            version="1",
            artifacts_dir=str(tmp_path),
            adapter=AdapterConfig(kind="scripted", mode="compromised"),
        ),
    )
    return summary, scenarios


def test_sarif_has_rules_severity_and_ordered_flow(
    mixed_run: tuple[SuiteRunSummary, list[ScenarioSpec]],
) -> None:
    from canary_ci.reporting.sarif import SarifExporter

    summary, scenarios = mixed_run
    sarif = SarifExporter.generate_sarif_dict(summary, scenarios)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 2
    assert float(rules[0]["properties"]["security-severity"]) >= 8.0
    result = next(result for result in run["results"] if result["ruleId"] == scenarios[0].id)
    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [step["location"]["message"]["text"].split(" · ")[0] for step in steps] == [
        "Origin",
        "Injection Vector",
        "Agent Turn",
        "Breach Sink",
    ]
    assert all(step["location"]["physicalLocation"]["region"]["startLine"] == 1 for step in steps)


def test_pr_markdown_and_json_roundtrip(
    mixed_run: tuple[SuiteRunSummary, list[ScenarioSpec]],
    tmp_path: Path,
) -> None:
    from canary_ci.reporting.markdown_pr import (
        MarkdownPRReporter,
        load_json_summary,
        write_json_summary,
    )

    summary, _ = mixed_run
    markdown = MarkdownPRReporter.generate_pr_markdown(summary)
    assert "BREACH DETECTED" in markdown and "Total | 2" in markdown
    assert "asi02-pr-diff-env-base64-exfil" in markdown
    assert "ASI02" in markdown and "git_post_pr_comment" in markdown
    assert "<details>" in markdown
    output = tmp_path / "summary.json"
    write_json_summary(output, summary)
    assert load_json_summary(output) == summary


def test_console_prints_provenance_and_replay(
    mixed_run: tuple[SuiteRunSummary, list[ScenarioSpec]],
) -> None:
    from canary_ci.reporting.console import (
        render_provenance_trees,
        render_replay_transcript,
        render_suite_summary,
    )

    summary, _ = mixed_run
    console = Console(record=True, width=160)
    render_suite_summary(summary, console)
    render_provenance_trees(summary, console)
    render_replay_transcript(replay_trace_file(summary.outcomes[0].trials[0].trace_path), console)
    text = console.export_text()
    assert "Breach Sink" in text and "canary-ci replay" in text
    assert "git_post_pr_comment" in text and "trial_completed" in text
