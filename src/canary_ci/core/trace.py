"""Append-only trace recording and host credential redaction."""

import os
import re
from _thread import LockType
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from threading import Lock
from time import time_ns
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .constants import SENSITIVE_HOST_ENV_PREFIXES
from .errors import ConfigurationError

_REDACTION = "[REDACTED_HOST_CREDENTIAL]"
_PAYLOAD_ADAPTER: TypeAdapter[dict[str, Any]] = TypeAdapter(dict[str, Any])
type _TraceActor = Literal["harness", "agent", "environment", "defense_proxy", "peer_agent"]


class TraceEventType(StrEnum):
    TRIAL_STARTED = "trial_started"
    CANARY_SEEDED = "canary_seeded"
    INJECTION_PLANTED = "injection_planted"
    SESSION_STARTED = "session_started"
    TOOLS_LISTED = "tools_listed"
    TOOL_SCHEMA_MUTATED = "tool_schema_mutated"
    USER_PROMPT_SENT = "user_prompt_sent"
    AGENT_THOUGHT_OR_MESSAGE = "agent_message"
    TOOL_CALL = "tool_call"
    DEFENSE_DECISION = "defense_decision"
    TOOL_RESPONSE = "tool_response"
    HTTP_EGRESS_CAPTURED = "http_egress_captured"
    A2A_MESSAGE = "a2a_message"
    DOM_INTERACTION = "dom_interaction"
    APPROVAL_REQUESTED = "approval_requested"
    MEMORY_MUTATED = "memory_mutated"
    BREACH_DETECTED = "breach_detected"
    TRIAL_COMPLETED = "trial_completed"


class TraceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int
    timestamp_us: int
    run_id: str
    scenario_id: str
    trial_index: int
    session_id: str
    turn_index: int
    event_type: TraceEventType
    actor: _TraceActor
    tool_name: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


def _redact(value: Any, secrets: re.Pattern[str]) -> Any:
    if isinstance(value, str):
        return secrets.sub(_REDACTION, value)
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            name = secrets.sub(_REDACTION, key)
            candidate = name
            suffix = 2
            # Preserve original keys and entries that redact to the same key.
            if name != key:
                while candidate in value or candidate in redacted:
                    candidate = f"{name} ({suffix})"
                    suffix += 1
            redacted[candidate] = _redact(item, secrets)
        return redacted
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    return value


class TraceWriter:
    """Record a single trial's events to a JSONL file."""

    def __init__(
        self,
        output_path: Path,
        run_id: str,
        scenario_id: str,
        trial_index: int,
        redact_values: Sequence[str] = (),
    ) -> None:
        self.output_path: Path = output_path
        self.run_id: str = run_id
        self.scenario_id: str = scenario_id
        self.trial_index: int = trial_index
        self.events: list[TraceEvent] = []
        self._lock: LockType = Lock()
        credentials = {value for value in redact_values if value}
        credentials.update(
            value
            for name, value in os.environ.items()
            if name.startswith(SENSITIVE_HOST_ENV_PREFIXES) and len(value) >= 8
        )
        pattern = "|".join(re.escape(value) for value in sorted(credentials, key=len, reverse=True))
        self._secrets: re.Pattern[str] | None = re.compile(pattern) if pattern else None

    def emit(
        self,
        event_type: TraceEventType,
        actor: _TraceActor,
        session_id: str,
        turn_index: int,
        tool_name: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> TraceEvent:
        try:
            # Normalize JSON-serializable values before scrubbing and storing them.
            clean_payload = _PAYLOAD_ADAPTER.validate_json(
                _PAYLOAD_ADAPTER.dump_json(payload or {})
            )
        except ValueError:
            raise ConfigurationError(f"{self.output_path}: invalid trace payload") from None
        if self._secrets is not None:
            clean_payload = cast(dict[str, Any], _redact(clean_payload, self._secrets))

        with self._lock:
            event = TraceEvent(
                seq=len(self.events),
                timestamp_us=time_ns() // 1_000,
                run_id=self.run_id,
                scenario_id=self.scenario_id,
                trial_index=self.trial_index,
                session_id=session_id,
                turn_index=turn_index,
                event_type=event_type,
                actor=actor,
                tool_name=tool_name,
                payload=clean_payload,
            )
            try:
                with self.output_path.open("a", encoding="utf-8", newline="\n") as sink:
                    sink.write(event.model_dump_json() + "\n")
                    sink.flush()
            except OSError as exc:
                raise ConfigurationError(f"{self.output_path}: {exc.strerror}") from exc
            self.events.append(event)
            return event


class TraceReader:
    """Read and validate the events stored in a JSONL file."""

    @staticmethod
    def read_jsonl(path: Path) -> list[TraceEvent]:
        events: list[TraceEvent] = []
        try:
            with path.open("rb") as source:
                for line_number, line in enumerate(source, start=1):
                    try:
                        events.append(TraceEvent.model_validate_json(line))
                    except ValidationError:
                        raise ConfigurationError(
                            f"{path}:{line_number}: invalid trace event"
                        ) from None
        except OSError as exc:
            raise ConfigurationError(f"{path}: {exc.strerror}") from exc
        return events
