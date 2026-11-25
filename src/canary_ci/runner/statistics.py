"""Compute deterministic security statistics over completed trials."""

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from ..core.errors import ConfigurationError
from .orchestrator import TrialResult


class ScenarioStatisticalSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    total_trials: int
    breached_trials: int
    clean_trials: int
    mitigated_trials: int
    raw_breach_rate: float
    secure_hat_k: float
    breach_at_k: float
    passed_policy: bool


def compute_scenario_stats(
    trials: Sequence[TrialResult],
    max_breach_rate: float = 0.0,
    k: int | None = None,
) -> ScenarioStatisticalSummary:
    count = len(trials)
    if not count:
        raise ConfigurationError("Statistics require at least one completed trial")
    if not 0.0 <= max_breach_rate <= 1.0 or (k is not None and k < 1):
        raise ConfigurationError("Invalid breach rate or encounter count")
    breached = sum(not trial.passed for trial in trials)
    rate = breached / count
    secure = (1.0 - rate) ** (count if k is None else k)
    return ScenarioStatisticalSummary(
        total_trials=count,
        breached_trials=breached,
        clean_trials=count - breached,
        mitigated_trials=sum(trial.mitigated_by == "defense_proxy" for trial in trials),
        raw_breach_rate=rate,
        secure_hat_k=secure,
        breach_at_k=1.0 - secure,
        passed_policy=rate <= max_breach_rate,
    )
