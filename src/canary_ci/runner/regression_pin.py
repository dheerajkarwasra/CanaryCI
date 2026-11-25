"""Convert a captured failure into a portable scripted regression scenario."""

import base64
import os
import re
from collections.abc import Iterable
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import quote

import yaml
from pydantic import ValidationError

from ..canary.seeder import GeneratedCanary
from ..core.errors import ConfigurationError
from ..core.models import ScenarioSpec, ScriptedReplaySpec, load_scenario_yaml
from ..core.trace import TraceEventType
from .suite_runner import _trace_canaries, replay_trace_file


def _canary_macros(canaries: Iterable[GeneratedCanary]) -> dict[str, str]:
    replacements: dict[str, str] = {}
    for canary in canaries:
        value = canary.full_value
        variants = {
            "": value,
            "base64:": base64.b64encode(value.encode()).decode(),
            "base64_offset1:": base64.b64encode(f'{{"k":"{value}"}}'.encode()).decode(),
            "hex:": value.encode().hex(),
            "url:": quote(value, safe=""),
            "reverse:": value[::-1],
            "chunk1:": canary.core_token[:12],
            "chunk2:": canary.core_token[12:],
        }
        for prefix, encoded in variants.items():
            if encoded:
                replacements.setdefault(encoded, "{{" + prefix + "canary." + canary.id + "}}")
    return replacements


def _replace(value: Any, pattern: re.Pattern[str], replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return pattern.sub(lambda match: replacements[match[0]], value)
    if isinstance(value, dict):
        return {key: _replace(item, pattern, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace(item, pattern, replacements) for item in value]
    return value


class RegressionPinner:
    @staticmethod
    def pin_failed_trace(
        trace_path: Path,
        output_dir: Path,
        custom_id: str | None = None,
    ) -> Path:
        report = replay_trace_file(trace_path)
        if report.passed:
            raise ConfigurationError("Regression pinning requires a failed trace")
        scenario = report.scenario
        macros = _canary_macros(_trace_canaries(report.events).values())
        pattern = (
            re.compile(
                "|".join(re.escape(value) for value in sorted(macros, key=len, reverse=True))
            )
            if macros
            else None
        )
        steps: dict[str, dict[str, Any]] = {
            session.id: {"session_id": session.id, "calls": []} for session in scenario.sessions
        }
        for event in report.events:
            step = steps.get(event.session_id)
            if step is None:
                continue
            if event.event_type is TraceEventType.TOOL_CALL and event.tool_name is not None:
                step["calls"].append(
                    {"tool": event.tool_name, "args": event.payload.get("arguments", {})}
                )
            elif event.event_type is TraceEventType.AGENT_THOUGHT_OR_MESSAGE:
                step["final_response"] = event.payload.get("content", "")
        replay_steps = list(steps.values())
        if pattern is not None:
            replay_steps = _replace(replay_steps, pattern, macros)
        data = scenario.model_dump(mode="json", exclude_unset=True)
        data.update(
            id=f"{scenario.id[:57]}-pinned" if custom_id is None else custom_id,
            tags=list(dict.fromkeys([*scenario.tags, "pinned-regression"])),
            scripted_replay=ScriptedReplaySpec(
                benign_steps=scenario.scripted_replay.benign_steps
                if scenario.scripted_replay
                else [],
                compromised_steps=replay_steps,
            ).model_dump(mode="json"),
        )
        try:
            pinned = ScenarioSpec.model_validate(data)
        except ValidationError:
            raise ConfigurationError("Invalid pinned scenario") from None
        output = output_dir / f"{pinned.id}.yaml"
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(
                dir=output_dir, mode="w", encoding="utf-8", suffix=".yaml"
            ) as temp:
                yaml.safe_dump(data, temp, sort_keys=False)
                temp.flush()
                load_scenario_yaml(Path(temp.name))
                os.link(temp.name, output)
        except OSError as exc:
            raise ConfigurationError(f"Cannot write pinned scenario at {output}") from exc
        return output


pin_failed_trace = RegressionPinner.pin_failed_trace
