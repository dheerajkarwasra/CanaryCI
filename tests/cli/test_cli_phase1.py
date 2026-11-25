import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from canary_ci.core.models import load_scenario_yaml


def test_demo_reports_replays_and_pins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from canary_ci.cli.app import app

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    init = runner.invoke(app, ["init", "--demo"])
    assert init.exit_code == 0, init.output
    assert "canary-ci run --config canary.demo.yaml" in init.output
    assert runner.invoke(app, ["validate", "--config", "canary.demo.yaml"]).exit_code == 0
    breach = runner.invoke(
        app,
        [
            "run",
            "--config",
            "canary.demo.yaml",
            "--sarif",
            "out.sarif.json",
            "--json-report",
            "out.json",
            "--markdown-summary",
            "out.md",
        ],
    )
    assert breach.exit_code == 1, breach.output
    assert all(Path(name).is_file() for name in ("out.sarif.json", "out.json", "out.md"))
    results = json.loads(Path("out.json").read_text())
    assert len(results["outcomes"]) == 8
    assert all(not outcome["trials"][0]["passed"] for outcome in results["outcomes"])
    trace = results["outcomes"][0]["trials"][0]["trace_path"]
    assert runner.invoke(app, ["replay", trace, "--format", "json", "--reverify"]).exit_code == 1
    pinned = runner.invoke(app, ["pin", trace, "--out-dir", "pinned/"])
    assert pinned.exit_code == 0, pinned.output
    assert "pinned-regression" in load_scenario_yaml(next(Path("pinned").glob("*.yaml"))).tags
    benign = runner.invoke(app, ["run", "--config", "canary.demo.yaml", "--adapter-mode", "benign"])
    assert benign.exit_code == 0, benign.output


def test_invalid_config_and_available_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canary_ci.cli.app import app

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    Path("canary.yaml").write_text("invalid: true\n", encoding="utf-8")
    assert runner.invoke(app, ["validate"]).exit_code == 2
    listed = runner.invoke(app, ["list", "--format", "json"])
    assert listed.exit_code == 0, listed.output
    assert len(json.loads(listed.output)) == 25


def test_doctor_checks_local_prerequisites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from canary_ci.cli.app import app

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "127.0.0.1" in result.output and "Python" in result.output


def test_validate_resolves_canaries_in_selected_mock_profiles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from canary_ci.cli.app import app

    monkeypatch.chdir(tmp_path)
    Path("canary.yaml").write_text(
        """version: "1"
adapter: {kind: scripted}
scenario_paths: [scenario.yaml]
mock_profile_paths: [mock.yaml]
""",
        encoding="utf-8",
    )
    Path("scenario.yaml").write_text(
        """api_version: canary-ci/v1
id: fixture-profile
title: Fixture profile references
owasp_category: ASI02
severity: high
environment: {custom_mock_profiles: [fixture-mock]}
sessions: [{id: first, user_prompt: Review fixture records.}]
assertions: {}
""",
        encoding="utf-8",
    )
    Path("mock.yaml").write_text(
        """api_version: canary-ci/mock-v1
profile_id: fixture-mock
tools:
  - name: fixture_read
    description: Read a synthetic record.
    input_schema: {type: object}
    default_response: "{{canary.missing}}"
""",
        encoding="utf-8",
    )
    validated = CliRunner().invoke(app, ["validate"])
    assert validated.exit_code == 2
    assert "fixture-profile" in validated.output and "missing" in validated.output
