import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZipFile

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from canary_ci.cli.app import app
from canary_ci.core.errors import ScenarioValidationError
from canary_ci.core.models import AdapterConfig, CanaryConfig, DefenseProxyConfig, OwaspCategory
from canary_ci.core.trace import TraceEventType, TraceReader
from canary_ci.reporting.markdown_pr import load_json_summary
from canary_ci.runner.orchestrator import TrialOrchestrator
from canary_ci.runner.suite_runner import replay_trace_file
from canary_ci.scenarios import discover_scenarios

_ROOT = Path(__file__).resolve().parents[2]
_URL = re.compile(r'https?://[^\s"\'<>]+')
_EMAIL = re.compile(r"[\w.+%-]+@([a-zA-Z0-9.-]+\.[a-zA-Z][a-zA-Z0-9-]+)")


def test_catalog_covers_all_categories_and_reserved_domains() -> None:
    scenarios = discover_scenarios(["builtin:all"])
    assert len({scenario.id for scenario in scenarios}) == len(scenarios) == 40
    assert {scenario.owasp_category for scenario in scenarios} == set(OwaspCategory)
    for folder in (_ROOT / "src" / "canary_ci" / "scenarios", _ROOT / "examples"):
        for path in folder.rglob("*.yaml"):
            text = path.read_text(encoding="utf-8")
            domains = [urlsplit(url).hostname for url in _URL.findall(text)] + _EMAIL.findall(text)
            assert all(
                host
                and (
                    host in {"localhost", "127.0.0.1", "corp.internal"}
                    or host.endswith((".invalid", ".example", ".test", ".corp.internal"))
                )
                for host in domains
            ), path


def test_full_release_cli_run_diff_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    runner = CliRunner()
    assert runner.invoke(app, ["init"]).exit_code == 0
    base = ["run", "--pack", "builtin:all", "--adapter-mode"]
    vulnerable = runner.invoke(
        app, [*base, "compromised", "--json-report", "baseline.json", "--sarif", "full.sarif.json"]
    )
    assert vulnerable.exit_code == 1, vulnerable.output
    baseline = load_json_summary(Path("baseline.json"))
    assert len(baseline.outcomes) == 40
    assert all(not case.passed and case.trials[0].provenance_chains for case in baseline.outcomes)
    sarif_run = json.loads(Path("full.sarif.json").read_bytes())["runs"][0]
    assert len(sarif_run["tool"]["driver"]["rules"]) == len(sarif_run["results"]) == 40
    assert all(result["codeFlows"] for result in sarif_run["results"])
    protected = runner.invoke(app, [*base, "benign", "--json-report", "hardened.json"])
    assert protected.exit_code == 0, protected.output
    hardened = load_json_summary(Path("hardened.json"))
    assert len(hardened.outcomes) == 40
    assert all(case.passed and not case.trials[0].breaches for case in hardened.outcomes)
    compared = runner.invoke(
        app, ["diff", "baseline.json", "hardened.json", "--fail-on-regression"]
    )
    assert compared.exit_code == 0 and compared.output.count("| FIXED |") == 40
    assert runner.invoke(app, ["audit", "keygen", "--out-prefix", "release"]).exit_code == 0
    run_dir = Path(".canary") / "runs" / baseline.run_id
    archive = runner.invoke(
        app,
        [
            "audit",
            "export",
            "--run-dir",
            str(run_dir),
            "--out",
            "release.zip",
            "--signing-key",
            "release.key",
        ],
    )
    assert archive.exit_code == 0, archive.output
    assert (
        runner.invoke(
            app, ["audit", "verify", "release.zip", "--public-key", "release.pub"]
        ).exit_code
        == 0
    )
    with ZipFile("release.zip", "a") as modified_archive:
        modified_archive.writestr("unlisted.txt", "Unexpected member")
    assert runner.invoke(app, ["audit", "verify", "release.zip"]).exit_code == 1


def test_cli_reports_config_error_and_adapter_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    Path("canary.yaml").write_text("no: configuration", encoding="utf-8")
    assert runner.invoke(app, ["run"]).exit_code == 2
    Path("canary.yaml").write_text(
        yaml.safe_dump(
            {
                "version": "1",
                "adapter": {
                    "kind": "cli",
                    "command": [sys.executable, "-c", "raise SystemExit(4)"],
                },
            }
        ),
        encoding="utf-8",
    )
    failed = runner.invoke(app, ["run", "--scenario", "asi01-email-hijack-external-forward"])
    assert failed.exit_code == 3 and "exited with status 4" in failed.output


def test_pack_loader_checks_local_directories_and_duplicates(tmp_path: Path) -> None:
    scenario = (
        _ROOT
        / "src"
        / "canary_ci"
        / "scenarios"
        / "phase1_core"
        / "asi02-pr-diff-env-base64-exfil.yaml"
    )
    copy = tmp_path / "local.yaml"
    copy.write_bytes(scenario.read_bytes())
    assert [item.id for item in discover_scenarios([str(tmp_path)])] == [scenario.stem]
    with pytest.raises(ScenarioValidationError, match="Duplicate scenario ID"):
        discover_scenarios([str(tmp_path), "builtin:phase1_core"])
    with pytest.raises(ScenarioValidationError, match="Unknown built-in"):
        discover_scenarios(["builtin:missing"])
    with pytest.raises(ScenarioValidationError, match="does not exist"):
        discover_scenarios([str(tmp_path / "missing.yaml")])


@pytest.mark.parametrize("policy_mode", ["fail-open", "fail-closed", "rewrite"])
async def test_defense_failure_and_rewrites_preserve_replay_verdict(
    tmp_path: Path,
    policy_mode: str,
) -> None:
    scenario = next(
        item
        for item in discover_scenarios(["builtin:phase1_core"])
        if item.id == "asi02-pr-diff-env-base64-exfil"
    )

    def policy(request: httpx.Request) -> httpx.Response:
        call = json.loads(request.content)
        if call["tool_name"] != "git_post_pr_comment":
            return httpx.Response(200, json={"allow": True})
        if policy_mode == "rewrite":
            args = {**call["arguments"], "body": "Sanitized test record."}
            return httpx.Response(200, json={"allow": True, "modified_args": args})
        return httpx.Response(503)

    config = CanaryConfig(
        version="1",
        artifacts_dir=str(tmp_path),
        adapter=AdapterConfig(kind="scripted", mode="compromised"),
        defense_proxy=DefenseProxyConfig(
            kind="webhook_policy",
            policy_url="https://policy.example/check",
            fail_closed=policy_mode != "fail-open",
        ),
    )
    orchestrator = TrialOrchestrator(policy_transport=httpx.MockTransport(policy))
    trial = await orchestrator.execute_trial(scenario, config, "fixture", 0)
    assert trial.passed == (policy_mode != "fail-open")
    assert replay_trace_file(trial.trace_path, reverify=True).passed == trial.passed
    events = TraceReader.read_jsonl(trial.trace_path)
    decisions = [
        event
        for event in events
        if event.event_type is TraceEventType.DEFENSE_DECISION
        and event.tool_name == "git_post_pr_comment"
    ]
    assert len(decisions) == 1
    assert (decisions[0].payload["action"] == "blocked") == (policy_mode == "fail-closed")
    if policy_mode == "rewrite":
        assert decisions[0].payload["effective_arguments"]["body"] == "Sanitized test record."


def test_multi_trial_markdown_and_ephemeral_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CANARY_SIGNING_PRIVATE_KEY", raising=False)
    runner = CliRunner()
    assert runner.invoke(app, ["init", "--demo"]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "run",
            "--demo",
            "--concurrency",
            "2",
            "--trials",
            "2",
            "--scenario",
            "asi01-email-hijack-external-forward",
            "--markdown-summary",
            "report.md",
            "--json-report",
            "run.json",
        ],
    )
    assert result.exit_code == 1, result.output
    markdown = Path("report.md").read_text(encoding="utf-8")
    assert "secure^k" in markdown and "| 2/2 | 100.00% | 0.00% | 100.00% |" in markdown
    summary = load_json_summary(Path("run.json"))
    run_dir = Path(".canary") / "runs" / summary.run_id
    assert (
        runner.invoke(
            app, ["audit", "export", "--run-dir", str(run_dir), "--out", "ephemeral.zip"]
        ).exit_code
        == 0
    )
    with ZipFile("ephemeral.zip") as bundle:
        assert json.loads(bundle.read("manifest.json"))["key_origin"] == "ephemeral"
    assert runner.invoke(app, ["audit", "verify", "ephemeral.zip"]).exit_code == 0
