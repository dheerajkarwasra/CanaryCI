"""Compare policy outcomes and validate time-limited scenario waivers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import date
from enum import StrEnum
from statistics import fmean
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from ..core.errors import ConfigurationError, ExpiredWaiverError
from ..core.models import OwaspCategory, Severity, WaiverSpec

if TYPE_CHECKING:
    from .suite_runner import ScenarioRunOutcome, SuiteRunSummary


class DiffStatus(StrEnum):
    NEW_REGRESSION = "NEW_REGRESSION"
    FIXED = "FIXED"
    KNOWN_FAIL = "KNOWN_FAIL"
    UNCHANGED_PASS = "UNCHANGED_PASS"  # noqa: S105 - Baseline status label.
    ADDED_PASS = "ADDED_PASS"  # noqa: S105 - Baseline status label.
    REMOVED = "REMOVED"


class ScenarioTrialMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    trial_count: int
    mean_duration_ms: float | None
    mean_tokens: float | None


class ScenarioDiffEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str
    owasp_category: OwaspCategory | None
    severity: Severity | None
    status: DiffStatus
    baseline_breach_rate: float | None
    current_breach_rate: float
    baseline_metrics: ScenarioTrialMetrics | None = None
    current_metrics: ScenarioTrialMetrics | None = None
    mean_duration_delta_ms: float | None = None
    mean_token_delta: float | None = None


class BaselineDiffReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    counts: dict[DiffStatus, int]
    entries: list[ScenarioDiffEntry]
    has_new_regressions: bool


def _status(previous: ScenarioRunOutcome | None, current: ScenarioRunOutcome | None) -> DiffStatus:
    if current is None:
        return DiffStatus.REMOVED
    if previous is None:
        return DiffStatus.ADDED_PASS if current.passed else DiffStatus.NEW_REGRESSION
    if current.passed:
        return DiffStatus.UNCHANGED_PASS if previous.passed else DiffStatus.FIXED
    if (previous.security_passed and not current.security_passed) or (
        previous.tasks_passed and not current.tasks_passed
    ):
        return DiffStatus.NEW_REGRESSION
    return DiffStatus.KNOWN_FAIL


def _breach_rate(outcome: ScenarioRunOutcome) -> float:
    if outcome.stats is not None:
        return outcome.stats.raw_breach_rate
    return (
        (sum(not trial.passed for trial in outcome.trials) / len(outcome.trials))
        if outcome.trials
        else 0.0
    )


def _trial_metrics(outcome: ScenarioRunOutcome | None) -> ScenarioTrialMetrics | None:
    if outcome is None:
        return None
    trials = outcome.trials
    tokens = [
        trial.token_usage["prompt_tokens"] + trial.token_usage["completion_tokens"]
        for trial in trials
        if "prompt_tokens" in trial.token_usage and "completion_tokens" in trial.token_usage
    ]
    return ScenarioTrialMetrics(
        trial_count=len(trials),
        mean_duration_ms=fmean(trial.duration_ms for trial in trials) if trials else None,
        mean_tokens=fmean(tokens) if tokens and len(tokens) == len(trials) else None,
    )


def _delta(before: float | None, after: float | None) -> float | None:
    return None if before is None or after is None else after - before


def compare_summaries(baseline: SuiteRunSummary, current: SuiteRunSummary) -> BaselineDiffReport:
    validate_summary_waivers(baseline)
    validate_summary_waivers(current)
    before = {outcome.scenario_id: outcome for outcome in baseline.outcomes}
    after = {outcome.scenario_id: outcome for outcome in current.outcomes}
    if len(before) != len(baseline.outcomes) or len(after) != len(current.outcomes):
        raise ConfigurationError("Baseline comparison requires unique scenario IDs")
    entries: list[ScenarioDiffEntry] = []
    for id_ in sorted(before.keys() | after.keys()):
        previous, latest = before.get(id_), after.get(id_)
        metadata = latest or before[id_]
        left, right = _trial_metrics(previous), _trial_metrics(latest)
        entries.append(
            ScenarioDiffEntry(
                scenario_id=id_,
                owasp_category=metadata.owasp_category,
                severity=metadata.severity,
                status=_status(previous, latest),
                baseline_breach_rate=_breach_rate(previous) if previous is not None else None,
                current_breach_rate=_breach_rate(latest) if latest is not None else 0.0,
                baseline_metrics=left,
                current_metrics=right,
                mean_duration_delta_ms=_delta(left.mean_duration_ms, right.mean_duration_ms)
                if left and right
                else None,
                mean_token_delta=_delta(left.mean_tokens, right.mean_tokens)
                if left and right
                else None,
            )
        )
    counts = Counter(entry.status for entry in entries)
    return BaselineDiffReport(
        counts={status: counts[status] for status in DiffStatus},
        entries=entries,
        has_new_regressions=counts[DiffStatus.NEW_REGRESSION] > 0,
    )


def _comparison_cell(left: float | None, right: float | None, delta: float | None) -> str:
    before = "—" if left is None else f"{left:.1f}"
    after = "—" if right is None else f"{right:.1f}"
    change = "" if delta is None else f" ({delta:+.1f})"
    return f"{before} → {after}{change}"


def format_diff_markdown(report: BaselineDiffReport) -> str:
    lines = [
        "## CanaryCI baseline comparison",
        "",
        "Means cover completed trials. Deltas are current minus baseline. "
        "An em dash indicates an unavailable measurement.",
        "",
        "| Scenario | OWASP | Severity | Status | Baseline breach rate | Current breach rate | "
        "Trials (before → after) | Mean duration (ms) | Mean tokens per trial |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in report.entries:
        previous = (
            f"{entry.baseline_breach_rate:.2%}" if entry.baseline_breach_rate is not None else "—"
        )
        current = "—" if entry.status is DiffStatus.REMOVED else f"{entry.current_breach_rate:.2%}"
        id_ = " ".join(entry.scenario_id.split()).replace("|", "&#124;").replace("<", "&lt;")
        left, right = entry.baseline_metrics, entry.current_metrics
        counts = f"{left.trial_count if left else '—'} → {right.trial_count if right else '—'}"
        duration = _comparison_cell(
            left.mean_duration_ms if left else None,
            right.mean_duration_ms if right else None,
            entry.mean_duration_delta_ms,
        )
        tokens = _comparison_cell(
            left.mean_tokens if left else None,
            right.mean_tokens if right else None,
            entry.mean_token_delta,
        )
        lines.append(
            f"| {id_} | {entry.owasp_category or '—'} | {entry.severity or '—'} | "
            f"{entry.status} | {previous} | {current} | {counts} | {duration} | {tokens} |"
        )
    return "\n".join(lines) + "\n"


def validate_waivers(
    waivers: Sequence[WaiverSpec], reference_date: date | None = None
) -> dict[str, WaiverSpec]:
    today = reference_date or date.today()
    active: dict[str, WaiverSpec] = {}
    for waiver in waivers:
        if waiver.expires_at < today:
            raise ExpiredWaiverError(
                f"Waiver for {waiver.scenario_id} owned by {waiver.owner} "
                f"expired {waiver.expires_at}"
            )
        if waiver.scenario_id in active:
            raise ConfigurationError(f"Duplicate waiver for {waiver.scenario_id}")
        active[waiver.scenario_id] = waiver
    return active


def validate_summary_waivers(summary: SuiteRunSummary) -> None:
    validate_waivers([outcome.waiver for outcome in summary.outcomes if outcome.waiver is not None])


class BaselineDiffer:
    compare_summaries = staticmethod(compare_summaries)
    format_diff_markdown = staticmethod(format_diff_markdown)
    validate_waivers = staticmethod(validate_waivers)
