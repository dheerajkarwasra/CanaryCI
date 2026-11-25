"""Evaluate explicit task postconditions against end-of-session fixture state."""

import hashlib
import json
from collections.abc import Mapping
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from ..canary.seeder import CanarySeeder, GeneratedCanary
from ..core.errors import ConfigurationError
from ..core.models import ScenarioSpec

type _Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class TaskObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    path: list[str | int]
    sha256: _Sha256 | None
    expected_sha256: _Sha256


def _digest(value: Any) -> str:
    try:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("Task assertions require finite JSON values") from exc
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _observed_digest(state: Mapping[str, Any], path: list[str | int]) -> str | None:
    value: Any = state
    for part in path:
        if isinstance(part, str):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        else:
            if not isinstance(value, list) or not 0 <= part < len(value):
                return None
            value = value[part]
    return _digest(value)


def observe_task_state(
    scenario: ScenarioSpec,
    session_id: str,
    state: dict[str, Any],
    canaries: Mapping[str, GeneratedCanary],
) -> dict[str, TaskObservation]:
    return {
        check.id: TaskObservation(
            session_id=session_id,
            path=check.path,
            sha256=_observed_digest(state, check.path),
            expected_sha256=_digest(CanarySeeder.render_template(check.equals, canaries)),
        )
        for check in scenario.assertions.task_completion
        if (check.session_id or scenario.sessions[-1].id) == session_id
    }


def failed_task_checks(
    scenario: ScenarioSpec,
    observations: Mapping[str, TaskObservation],
    override_canaries: Mapping[str, GeneratedCanary] | None = None,
) -> list[str]:
    failed = []
    for check in scenario.assertions.task_completion:
        observation = observations.get(check.id)
        if (
            observation is None
            or observation.session_id != (check.session_id or scenario.sessions[-1].id)
            or observation.path != check.path
        ):
            raise ConfigurationError(f"Missing matching task observation for {check.id}")
        expected = observation.expected_sha256
        if override_canaries is not None:
            expected = _digest(CanarySeeder.render_template(check.equals, override_canaries))
        if observation.sha256 != expected:
            failed.append(check.id)
    return failed
