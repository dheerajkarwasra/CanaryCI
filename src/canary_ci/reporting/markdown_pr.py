"""Render GitHub-compatible Markdown and read or write JSON summaries."""

from html import escape
from pathlib import Path

from pydantic import ValidationError

from ..core.errors import ConfigurationError
from ..runner.suite_runner import SuiteRunSummary
from . import _STAGE_LABELS


def _cell(value: str) -> str:
    return escape(" ".join(value.split())).replace("|", "&#124;").replace("`", "&#96;")


def write_json_summary(path: Path, summary: SuiteRunSummary) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(summary.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"Cannot write JSON report at {path}") from exc


def load_json_summary(path: Path) -> SuiteRunSummary:
    try:
        return SuiteRunSummary.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise ConfigurationError(f"Cannot read JSON report at {path}") from exc


class MarkdownPRReporter:
    @staticmethod
    def generate_pr_markdown(summary: SuiteRunSummary) -> str:
        breached = [outcome for outcome in summary.outcomes if not outcome.security_passed]
        trials = [trial for outcome in summary.outcomes for trial in outcome.trials]
        mitigated = sum(trial.mitigated_by == "defense_proxy" for trial in trials)
        duration = sum(trial.duration_ms for trial in trials)
        status = "PASS" if summary.passed else "BREACH DETECTED" if breached else "TASK INCOMPLETE"
        lines = [
            f"## CanaryCI · {status}",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Total | {len(summary.outcomes)} |",
            f"| Passed | {sum(case.passed for case in summary.outcomes)} |",
            f"| Breached | {len(breached)} |",
            f"| Mitigated by Defense | {mitigated} |",
            f"| Duration | {duration:.1f} ms |",
        ]
        checked = [trial for trial in trials if trial.task_completed is not None]
        if checked:
            completed = sum(trial.task_completed is True for trial in checked)
            lines.append(f"| Tasks completed (trials) | {completed}/{len(checked)} |")
            for trial in checked:
                if trial.task_failures:
                    failed = ", ".join(_cell(name) for name in trial.task_failures)
                    lines.extend(
                        [
                            "",
                            f"- {_cell(trial.scenario_id)} · trial {trial.trial_index} · "
                            f"failed task assertions: {failed}",
                        ]
                    )
        multi_trial = [outcome for outcome in summary.outcomes if len(outcome.trials) > 1]
        if multi_trial:
            lines.extend(
                [
                    "",
                    "| Scenario | Breached | Breach rate | secure^k | breach@k |",
                    "| --- | ---: | ---: | ---: | ---: |",
                ]
            )
            for outcome in multi_trial:
                if stats := outcome.stats:
                    breached_count = f"{stats.breached_trials}/{stats.total_trials}"
                    lines.append(
                        f"| {_cell(outcome.scenario_id)} | {breached_count} "
                        f"| {stats.raw_breach_rate:.2%} | {stats.secure_hat_k:.2%} "
                        f"| {stats.breach_at_k:.2%} |"
                    )
        if breached:
            lines.extend(
                [
                    "",
                    "| Scenario | OWASP | Severity | Breach / Transform | Sink Tool |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for outcome in breached:
                for trial in outcome.trials:
                    for breach in trial.breaches:
                        kind = " / ".join(filter(None, (breach.breach_kind, breach.transform_used)))
                        lines.append(
                            "| "
                            + " | ".join(
                                _cell(value)
                                for value in (
                                    outcome.scenario_id,
                                    breach.owasp_category,
                                    breach.severity,
                                    kind,
                                    breach.sink_tool or "Agent response",
                                )
                            )
                            + " |"
                        )
            lines.extend(["", "<details>", "<summary>Breach provenance</summary>", ""])
            for outcome in breached:
                for trial in outcome.trials:
                    for chain in trial.provenance_chains:
                        steps = " → ".join(
                            f"{_STAGE_LABELS[node.stage]} · {_cell(node.summary)}"
                            for node in chain.nodes
                        )
                        lines.append(f"- **{_cell(outcome.scenario_id)}** · {steps}")
            lines.extend(["", "</details>"])
        return "\n".join(lines) + "\n"
