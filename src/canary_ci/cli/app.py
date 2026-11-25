"""Run CanaryCI evaluations and work with their saved artifacts."""

import asyncio
import json
import os
import re
import socket
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from enum import StrEnum
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..core.errors import CanaryCIError, ConfigurationError, ScenarioValidationError
from ..core.models import (
    EnvironmentSpec,
    MockProfileSpec,
    OwaspCategory,
    ScenarioSpec,
    load_config_yaml,
)
from ..environments.custom_profile import load_custom_profiles
from ..environments.enterprise_mocks import build_composite_environment
from ..environments.mcp_server import EphemeralMCPServer
from ..reporting.audit_bundle import (
    export_signed_audit_bundle,
    generate_ed25519_keypair,
    read_signing_key,
    verify_signed_audit_bundle,
)
from ..reporting.console import (
    render_provenance_trees,
    render_replay_transcript,
    render_suite_summary,
)
from ..reporting.junit import write_junit
from ..reporting.markdown_pr import MarkdownPRReporter, load_json_summary, write_json_summary
from ..reporting.sarif import SarifExporter
from ..runner.baseline_diff import compare_summaries, format_diff_markdown, validate_waivers
from ..runner.regression_pin import RegressionPinner
from ..runner.suite_runner import SuiteRunner, replay_trace_file
from ..scenarios import discover_scenarios

app = typer.Typer(no_args_is_help=True)
audit_app = typer.Typer(no_args_is_help=True, help="Sign and verify run evidence.")
app.add_typer(audit_app, name="audit")
_REFERENCE = re.compile(r"\{\{(?:[a-z0-9_]+:)?canary\.([^{}]+)\}\}")
_STARTER = """# CanaryCI configuration. See canary-ci run --help for overrides.
version: "1"
project_name: "local-agent"

# Start with the packaged fixtures and add local scenarios as needed.
scenario_paths: ["builtin:phase1_core"]
include_tags: ["smoke"]
artifacts_dir: ".canary"

# The scripted adapter runs offline. Set a model and adapter to test your agent.
adapter:
  kind: "scripted"
  mode: "benign"
"""


class _Mode(StrEnum):
    BENIGN = "benign"
    COMPROMISED = "compromised"


class _ListFormat(StrEnum):
    TABLE = "table"
    JSON = "json"


class _ReplayFormat(StrEnum):
    RICH = "rich"
    JSON = "json"


@contextmanager
def _command_errors() -> Iterator[None]:
    try:
        yield
    except CanaryCIError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(exc.exit_code) from None
    except OSError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from None


@app.command()
def init(path: Path = Path("."), demo: bool = False, force: bool = False) -> None:
    """Write configuration for a local project."""
    with _command_errors():
        configs = {path / "canary.yaml": _STARTER}
        if demo:
            configs[path / "canary.demo.yaml"] = _STARTER.replace(
                'mode: "benign"', 'mode: "compromised"'
            )
        for destination in configs:
            if destination.exists() and not force:
                raise ConfigurationError(f"Configuration already exists at {destination}")
        path.mkdir(parents=True, exist_ok=True)
        for destination, content in configs.items():
            with destination.open("w" if force else "x", encoding="utf-8") as handle:
                handle.write(content)
            typer.echo(f"Wrote {destination}")
        if demo:
            demo_file = "canary.demo.yaml" if path == Path(".") else str(path / "canary.demo.yaml")
            typer.echo(f"canary-ci run --config {demo_file}")
            typer.echo(f"canary-ci run --config {demo_file} --adapter-mode benign")


def _validate_references(
    scenarios: Sequence[ScenarioSpec], profiles: Sequence[MockProfileSpec] = ()
) -> None:
    profile_refs = {
        profile.profile_id: set(_REFERENCE.findall(profile.model_dump_json()))
        for profile in profiles
    }
    for scenario in scenarios:
        canary_ids = {canary.id for canary in scenario.canaries}
        if len(canary_ids) != len(scenario.canaries):
            raise ScenarioValidationError(f"{scenario.id}: duplicate canary IDs")
        references = set(_REFERENCE.findall(scenario.model_dump_json()))
        if scenario.environment:
            for profile_id in scenario.environment.custom_mock_profiles:
                references.update(profile_refs.get(profile_id, ()))
        missing = references - canary_ids
        if missing:
            raise ScenarioValidationError(
                f"{scenario.id}: unknown canaries {', '.join(sorted(missing))}"
            )


@app.command()
def validate(config: Path = Path("canary.yaml"), scenarios: list[str] | None = None) -> None:
    """Validate configuration, mock profiles, and scenario references."""
    with _command_errors():
        settings = load_config_yaml(config)
        if settings.policy:
            validate_waivers(settings.policy.waivers)
        loaded = discover_scenarios(scenarios or settings.scenario_paths)
        profiles = load_custom_profiles(
            [
                profile
                for scenario in loaded
                if scenario.environment
                for profile in scenario.environment.custom_mock_profiles
            ],
            settings.mock_profile_paths,
        )
        _validate_references(loaded, profiles)
        typer.echo(f"Validated {len(loaded)} scenarios")


@app.command("list")
def list_scenarios(
    pack: str = "builtin:phase1_core",
    tag: str | None = None,
    owasp: OwaspCategory | None = None,
    output_format: Annotated[_ListFormat, typer.Option("--format")] = _ListFormat.TABLE,
) -> None:
    """List available scenarios."""
    with _command_errors():
        if pack in {"all", "phase1_core", "phase2_persistence", "phase3_multimodal_a2a"}:
            pack = f"builtin:{pack}"
        selected = [
            scenario
            for scenario in discover_scenarios([pack])
            if (tag is None or tag in scenario.tags)
            and (owasp is None or owasp == scenario.owasp_category)
        ]
        if output_format == _ListFormat.JSON:
            typer.echo(
                json.dumps(
                    [
                        scenario.model_dump(
                            mode="json",
                            include={
                                "id",
                                "title",
                                "owasp_category",
                                "severity",
                                "tier",
                                "tags",
                            },
                        )
                        for scenario in selected
                    ],
                    indent=2,
                )
            )
            return
        table = Table("Scenario", "OWASP", "Severity", "Tier", "Title")
        for scenario in selected:
            table.add_row(
                scenario.id,
                scenario.owasp_category,
                scenario.severity,
                scenario.tier,
                scenario.title,
            )
        Console().print(table)


@app.command()
def run(
    config: Path = Path("canary.yaml"),
    scenario: list[str] | None = None,
    tag: list[str] | None = None,
    owasp: OwaspCategory | None = None,
    concurrency: Annotated[int | None, typer.Option(min=1, max=64)] = None,
    trials: Annotated[int | None, typer.Option(min=1, max=100)] = None,
    seed: str | None = None,
    adapter_mode: _Mode | None = None,
    sarif: Path | None = None,
    json_report: Path | None = None,
    junit: Annotated[Path | None, typer.Option(help="Write JUnit XML results.")] = None,
    markdown_summary: Path | None = None,
    keep_sandbox: bool = False,
    fail_fast: bool = False,
    demo: bool = False,
    baseline: Path | None = None,
    pack: str | None = None,
) -> None:
    """Execute a suite and report any breached scenarios."""
    with _command_errors():
        if demo and config == Path("canary.yaml"):
            config = Path("canary.demo.yaml")
        settings = load_config_yaml(config)
        if adapter_mode is not None:
            if settings.adapter.kind != "scripted":
                raise ConfigurationError("--adapter-mode requires the scripted adapter")
            settings = settings.model_copy(
                update={
                    "adapter": settings.adapter.model_copy(
                        update={"mode": adapter_mode.value},
                    )
                }
            )
        if concurrency is not None:
            settings = settings.model_copy(update={"concurrency": concurrency})
        if seed is not None:
            settings = settings.model_copy(update={"seed": seed})
        if pack in {"all", "phase1_core", "phase2_persistence", "phase3_multimodal_a2a"}:
            pack = f"builtin:{pack}"
        specs = discover_scenarios([pack] if pack is not None else settings.scenario_paths)
        _validate_references(specs)
        summary = asyncio.run(
            SuiteRunner().run(
                specs,
                settings,
                scenario_ids=scenario or (),
                include_tags=tag if tag is not None or pack is None else (),
                owasp_category=owasp,
                fail_fast=fail_fast,
                keep_sandbox=keep_sandbox,
                baseline=load_json_summary(baseline) if baseline is not None else None,
                trials_override=trials,
            )
        )
        if not summary.outcomes:
            raise ConfigurationError("No scenarios match the requested filters")
        render_suite_summary(summary)
        render_provenance_trees(summary)
        if summary.baseline_diff is not None:
            typer.echo(format_diff_markdown(summary.baseline_diff))
        artifact = Path(settings.adapter.system_prompt_file or config)
        run_dir = Path(settings.artifacts_dir) / "runs" / summary.run_id
        SarifExporter.write_sarif(
            run_dir / "results.sarif.json", summary, specs, artifact.as_posix()
        )
        write_json_summary(run_dir / "summary.json", summary)
        if sarif is not None:
            SarifExporter.write_sarif(sarif, summary, specs, artifact.as_posix())
        if json_report is not None:
            write_json_summary(json_report, summary)
        if junit is not None:
            write_junit(junit, summary)
        if markdown_summary is not None:
            markdown_summary.parent.mkdir(parents=True, exist_ok=True)
            markdown_summary.write_text(
                MarkdownPRReporter.generate_pr_markdown(summary), encoding="utf-8"
            )
        elif github_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(github_summary).open("a", encoding="utf-8") as handle:
                handle.write(MarkdownPRReporter.generate_pr_markdown(summary))
        if not summary.passed:
            raise typer.Exit(1)


@app.command()
def diff(
    baseline_json: Path,
    current_json: Path,
    markdown_out: Path | None = None,
    fail_on_regression: bool = False,
    json_out: Path | None = None,
) -> None:
    """Compare two saved run summaries."""
    with _command_errors():
        report = compare_summaries(
            load_json_summary(baseline_json), load_json_summary(current_json)
        )
        markdown = format_diff_markdown(report)
        if markdown_out is not None:
            markdown_out.parent.mkdir(parents=True, exist_ok=True)
            markdown_out.write_text(markdown, encoding="utf-8")
        else:
            typer.echo(markdown, nl=False)
        if json_out is not None:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        if fail_on_regression and report.has_new_regressions:
            raise typer.Exit(1)


@app.command()
def replay(
    trace_file: Path,
    reverify: bool = False,
    output_format: Annotated[_ReplayFormat, typer.Option("--format")] = _ReplayFormat.RICH,
) -> None:
    """Read and optionally reverify a saved trial without an agent."""
    with _command_errors():
        report = replay_trace_file(trace_file, reverify=reverify)
        if output_format == _ReplayFormat.JSON:
            typer.echo(report.model_dump_json(indent=2))
        else:
            render_replay_transcript(report)
        if reverify and not report.passed:
            raise typer.Exit(1)


@app.command()
def pin(
    trace_file: Path,
    out_dir: Path = Path("scenarios/pinned"),
    custom_id: Annotated[str | None, typer.Option("--id")] = None,
) -> None:
    """Save a failed trial as a regression scenario."""
    with _command_errors():
        typer.echo(str(RegressionPinner.pin_failed_trace(trace_file, out_dir, custom_id)))


@app.command()
def doctor(config: Path | None = None) -> None:
    """Check the Python runtime, optional tools, and local permissions."""
    with _command_errors():
        typer.echo(f"CanaryCI {__version__} · Python {sys.version.split()[0]}")
        for extra in ("litellm", "playwright"):
            typer.echo(
                f"{extra} {'installed' if find_spec(extra) else 'optional extra unavailable'}"
            )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
        typer.echo("127.0.0.1 loopback bind passed")
        settings_path = config or Path("canary.yaml")
        settings = (
            load_config_yaml(settings_path)
            if config is not None or settings_path.exists()
            else None
        )
        root = Path(settings.artifacts_dir) if settings else Path(".canary")
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryFile(dir=root) as handle:
            handle.write(b"canary-ci")
        typer.echo(f"Artifact directory {root} is writable")
        if settings and settings.adapter.kind == "litellm":
            keys = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY")
            key_present = any(os.getenv(key) for key in keys)
            typer.echo(f"Provider API key present · {'yes' if key_present else 'no'}")


@audit_app.command("keygen")
def audit_keygen(out_prefix: Path = Path("canary-signing")) -> None:
    """Generate private and public Ed25519 PEM files."""
    with _command_errors():
        private, public = generate_ed25519_keypair(out_prefix)
        typer.echo(f"Wrote {private} and {public}")


@audit_app.command("export")
def audit_export(
    run_dir: Annotated[Path, typer.Option()],
    out: Annotated[Path, typer.Option()],
    signing_key: str | None = None,
) -> None:
    """Package and sign a completed run."""
    with _command_errors():
        pem = read_signing_key(os.environ.get(signing_key, signing_key)) if signing_key else None
        typer.echo(str(export_signed_audit_bundle(run_dir, out, pem)))


@audit_app.command("verify")
def audit_verify(bundle_zip: Path, public_key: Path | None = None) -> None:
    """Verify a signed bundle and every declared file."""
    with _command_errors():
        key = public_key.read_bytes() if public_key is not None else None
        result = verify_signed_audit_bundle(bundle_zip, key)
        typer.echo(f"Verified {result.verified_files} files for run {result.run_id}")


@app.command("internal-mcp-stdio", hidden=True)
def internal_mcp_stdio(state_file: Annotated[Path, typer.Option()]) -> None:
    """Serve a rendered environment fixture to a local MCP stdio client."""

    async def serve(spec: EnvironmentSpec) -> None:
        with TemporaryDirectory(prefix="canary_trial_") as sandbox:
            env = build_composite_environment(spec)
            await env.setup(Path(sandbox), spec.model_dump(mode="json", exclude_none=True))
            try:
                await EphemeralMCPServer(env, spec).serve_stdio()
            finally:
                await env.teardown()

    with _command_errors():
        try:
            spec = EnvironmentSpec.model_validate_json(state_file.read_bytes())
        except ValidationError:
            raise ConfigurationError(f"Invalid rendered MCP state file at {state_file}") from None
        asyncio.run(serve(spec))


if __name__ == "__main__":
    app()
