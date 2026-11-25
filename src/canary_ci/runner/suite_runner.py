"""Filter and run scenario suites, and replay saved trials offline."""

import asyncio
from collections.abc import Collection, Sequence
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from ..canary.detector import BreachDetector, DetectedBreach
from ..canary.provenance import BreachProvenance, ProvenanceBuilder
from ..canary.seeder import GeneratedCanary
from ..core.constants import SEVERITY_RANK
from ..core.errors import ConfigurationError
from ..core.models import (
    CanaryConfig,
    OwaspCategory,
    ScenarioSpec,
    ScenarioTier,
    Severity,
    WaiverSpec,
)
from ..core.trace import TraceEvent, TraceEventType, TraceReader
from .baseline_diff import (
    BaselineDiffReport,
    compare_summaries,
    validate_summary_waivers,
    validate_waivers,
)
from .orchestrator import TrialOrchestrator, TrialResult
from .statistics import ScenarioStatisticalSummary, compute_scenario_stats
from .task_completion import TaskObservation, failed_task_checks

_PROTECTED_HASHES = TypeAdapter(dict[str, str])


class ScenarioRunOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str
    trials: list[TrialResult]
    owasp_category: OwaspCategory | None = None
    severity: Severity | None = None
    waived: bool = False
    waiver: WaiverSpec | None = None
    stats: ScenarioStatisticalSummary | None = None

    @property
    def passed(self) -> bool:
        return self.security_passed and self.tasks_passed

    @property
    def tasks_passed(self) -> bool:
        return all(trial.task_completed is not False for trial in self.trials)

    @property
    def security_passed(self) -> bool:
        return self.waived or (
            self.stats.passed_policy if self.stats else all(trial.passed for trial in self.trials)
        )


class SuiteRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    outcomes: list[ScenarioRunOutcome]
    baseline_diff: BaselineDiffReport | None = None
    new_regressions_only: bool = False

    @property
    def passed(self) -> bool:
        if self.new_regressions_only and self.baseline_diff is not None:
            return not self.baseline_diff.has_new_regressions
        return all(outcome.passed for outcome in self.outcomes)


class ReplayReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_path: Path
    scenario: ScenarioSpec
    events: list[TraceEvent]
    breaches: list[DetectedBreach]
    provenance_chains: list[BreachProvenance]
    reverified: bool
    task_completed: bool | None = None
    task_failures: list[str] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.breaches and self.task_completed is not False


class SuiteRunner:
    def __init__(self, orchestrator: TrialOrchestrator | None = None) -> None:
        self._orchestrator: TrialOrchestrator = orchestrator or TrialOrchestrator()

    async def run(
        self,
        scenarios: Sequence[ScenarioSpec],
        config: CanaryConfig,
        *,
        scenario_ids: Collection[str] = (),
        include_tags: Collection[str] | None = None,
        exclude_tags: Collection[str] | None = None,
        owasp_category: OwaspCategory | None = None,
        tier: ScenarioTier | None = None,
        fail_fast: bool = False,
        keep_sandbox: bool = False,
        run_id: str | None = None,
        baseline: SuiteRunSummary | None = None,
        trials_override: int | None = None,
    ) -> SuiteRunSummary:
        if trials_override is not None and not 1 <= trials_override <= 100:
            raise ConfigurationError("The trial count must be between 1 and 100")
        policy = config.policy
        waivers = validate_waivers(policy.waivers) if policy else {}
        regressions_only = bool(baseline and policy and policy.fail_on_new_regressions_only)
        known_security_failures: set[str] = set()
        known_task_failures: set[str] = set()
        if baseline is not None:
            validate_summary_waivers(baseline)
            if regressions_only:
                known_task_failures = {
                    outcome.scenario_id for outcome in baseline.outcomes if not outcome.tasks_passed
                }
                known_security_failures = {
                    outcome.scenario_id
                    for outcome in baseline.outcomes
                    if not outcome.security_passed
                }
        includes = set(config.include_tags if include_tags is None else include_tags)
        excludes = set(config.exclude_tags if exclude_tags is None else exclude_tags)
        selected = [
            scenario
            for scenario in scenarios
            if (not scenario_ids or scenario.id in scenario_ids)
            and (not includes or includes.intersection(scenario.tags))
            and not excludes.intersection(scenario.tags)
            and (owasp_category is None or scenario.owasp_category == owasp_category)
            and (tier is None or scenario.tier == tier)
        ]
        if len({scenario.id for scenario in selected}) != len(selected):
            raise ConfigurationError("Duplicate scenario IDs in selected suite")
        actual_run_id = uuid4().hex if run_id is None else run_id
        semaphore = asyncio.Semaphore(config.concurrency)
        trial_counts = {
            scenario.id: trials_override or scenario.trials or config.trials
            for scenario in selected
        }
        thresholds = {scenario.id: 0.0 for scenario in selected}
        if policy is not None:
            thresholds = {
                scenario.id: policy.max_breach_rate
                if SEVERITY_RANK[scenario.severity] >= SEVERITY_RANK[policy.fail_on_severity]
                else 1.0
                for scenario in selected
            }
        breached: dict[str, int] = {}
        stop_after: TrialResult | None = None

        async def execute(scenario: ScenarioSpec, trial_index: int) -> TrialResult | None:
            nonlocal stop_after
            async with semaphore:
                if stop_after is not None:
                    return None
                result = await self._orchestrator.execute_trial(
                    scenario,
                    config,
                    config.seed,
                    trial_index,
                    run_id=actual_run_id,
                    keep_sandbox=keep_sandbox,
                )
                if (
                    fail_fast
                    and stop_after is None
                    and result.task_completed is False
                    and scenario.id not in known_task_failures
                ):
                    stop_after = result
                if (
                    fail_fast
                    and not result.passed
                    and scenario.id not in waivers
                    and scenario.id not in known_security_failures
                    and stop_after is None
                ):
                    count = breached.get(scenario.id, 0) + 1
                    breached[scenario.id] = count
                    if count / trial_counts[scenario.id] > thresholds[scenario.id]:
                        stop_after = result
                return result

        jobs = [
            asyncio.create_task(execute(scenario, index))
            for scenario in selected
            for index in range(trial_counts[scenario.id])
        ]
        by_scenario: dict[str, list[TrialResult]] = {}
        try:
            for next_job in asyncio.as_completed(jobs):
                result = await next_job
                if result is None:
                    continue
                by_scenario.setdefault(result.scenario_id, []).append(result)
                if result is stop_after:
                    break
        finally:
            for job in jobs:
                if not job.done():
                    job.cancel()
            await asyncio.gather(*jobs, return_exceptions=True)
        outcomes = []
        for scenario in selected:
            trials = sorted(by_scenario.get(scenario.id, ()), key=lambda trial: trial.trial_index)
            if not trials:
                continue
            stats = compute_scenario_stats(trials, thresholds[scenario.id])
            waiver = waivers.get(scenario.id) if stats.breached_trials else None
            outcomes.append(
                ScenarioRunOutcome(
                    scenario_id=scenario.id,
                    owasp_category=scenario.owasp_category,
                    severity=scenario.severity,
                    trials=trials,
                    stats=stats,
                    waived=waiver is not None,
                    waiver=waiver,
                )
            )
        summary = SuiteRunSummary(run_id=actual_run_id, outcomes=outcomes)
        if baseline is not None:
            summary = summary.model_copy(
                update={
                    "baseline_diff": compare_summaries(baseline, summary),
                    "new_regressions_only": regressions_only,
                }
            )
        return summary


def _scenario_from_trace(events: Sequence[TraceEvent]) -> ScenarioSpec:
    try:
        return ScenarioSpec.model_validate(events[0].payload.get("scenario"))
    except (IndexError, ValidationError):
        raise ConfigurationError("Trace does not contain a valid scenario snapshot") from None


def _trace_canaries(events: Sequence[TraceEvent]) -> dict[str, GeneratedCanary]:
    try:
        canaries = [
            GeneratedCanary.model_validate(event.payload.get("canary"))
            for event in events
            if event.event_type is TraceEventType.CANARY_SEEDED
        ]
    except ValidationError:
        raise ConfigurationError("Trace contains invalid canary metadata") from None
    if len(canaries) != len({canary.id for canary in canaries}):
        raise ConfigurationError("Trace contains duplicate canary IDs")
    return {canary.id: canary for canary in canaries}


def replay_trace_file(
    trace_path: Path,
    scenario: ScenarioSpec | None = None,
    reverify: bool = False,
) -> ReplayReport:
    events = TraceReader.read_jsonl(trace_path)
    if (
        not events
        or events[0].event_type is not TraceEventType.TRIAL_STARTED
        or events[-1].event_type is not TraceEventType.TRIAL_COMPLETED
    ):
        raise ConfigurationError("Trace does not contain a complete trial")
    start, end = events[0], events[-1]
    if any(
        (event.seq, event.run_id, event.scenario_id, event.trial_index)
        != (index, start.run_id, start.scenario_id, start.trial_index)
        for index, event in enumerate(events)
    ):
        raise ConfigurationError("Trace contains inconsistent trial metadata")
    use_captured_expectations = scenario is None
    scenario = _scenario_from_trace(events) if scenario is None else scenario
    if scenario.id != start.scenario_id:
        raise ConfigurationError("Trace scenario ID does not match the scenario")
    if reverify:
        canaries = _trace_canaries(events)
        if canaries.keys() != {canary.id for canary in scenario.canaries}:
            raise ConfigurationError("Trace canary IDs do not match the scenario")
        try:
            workspace = Path(start.payload["workspace_dir"])
        except (KeyError, TypeError):
            raise ConfigurationError("Trace is missing its workspace directory") from None
        try:
            raw_before = end.payload.get("protected_before")
            raw_after = end.payload.get("protected_after")
            before = (
                _PROTECTED_HASHES.validate_python(raw_before, strict=True)
                if raw_before is not None
                else None
            )
            after = (
                _PROTECTED_HASHES.validate_python(raw_after, strict=True)
                if raw_after is not None
                else None
            )
        except ValidationError:
            raise ConfigurationError(
                "Trace contains invalid protected file hash metadata"
            ) from None
        actions = [
            event
            for event in events
            if event.event_type
            not in {TraceEventType.BREACH_DETECTED, TraceEventType.TRIAL_COMPLETED}
        ]
        breaches = BreachDetector.evaluate_trial(
            actions,
            scenario,
            canaries,
            workspace,
            protected_before=before,
            protected_after=after,
        )
        chains = ProvenanceBuilder.build_all(breaches, actions, scenario)
    else:
        try:
            recorded = [
                event for event in events if event.event_type is TraceEventType.BREACH_DETECTED
            ]
            breaches = [
                DetectedBreach.model_validate(event.payload.get("breach")) for event in recorded
            ]
            chains = [
                BreachProvenance.model_validate(event.payload.get("provenance"))
                for event in recorded
            ]
        except ValidationError:
            raise ConfigurationError("Trace contains invalid breach metadata") from None
    task_failures = []
    if scenario.assertions.task_completion:
        try:
            observations = TypeAdapter(dict[str, TaskObservation]).validate_python(
                end.payload.get("task_observations"), strict=True
            )
        except ValidationError:
            raise ConfigurationError("Trace contains invalid task observations") from None
        task_failures = failed_task_checks(
            scenario, observations, None if use_captured_expectations else _trace_canaries(events)
        )
    return ReplayReport(
        task_completed=(not task_failures) if scenario.assertions.task_completion else None,
        task_failures=task_failures,
        trace_path=trace_path,
        scenario=scenario,
        events=events,
        breaches=breaches,
        provenance_chains=chains,
        reverified=reverify,
    )
