"""Reconstruct causal evidence for a breach from its trial trace."""

import json
from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..core.models import ScenarioSpec
from ..core.trace import TraceEvent, TraceEventType
from .detector import BreachKind, DetectedBreach

type _Stage = Literal["origin", "injection_vector", "agent_turn", "breach_sink"]
type _Severity = Literal["critical", "high", "medium", "low"]

_UNTRUSTED_CARRIERS = frozenset(
    {
        TraceEventType.TOOL_RESPONSE,
        TraceEventType.TOOLS_LISTED,
        TraceEventType.TOOL_SCHEMA_MUTATED,
        TraceEventType.A2A_MESSAGE,
        TraceEventType.DOM_INTERACTION,
    }
)
_AGENT_EVENTS = frozenset({TraceEventType.AGENT_THOUGHT_OR_MESSAGE, TraceEventType.TOOL_CALL})


class ProvenanceNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: _Stage
    event_seq: int
    turn_index: int
    summary: str
    detail: dict[str, Any]


class BreachProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    breach_id: str
    owasp_category: str
    severity: _Severity
    breach_kind: BreachKind
    canary_id: str | None = None
    transform_used: str | None = None
    sink_tool: str | None = None
    nodes: list[ProvenanceNode]
    remediation_hint: str


def _origin(breach: DetectedBreach, prior: list[TraceEvent]) -> ProvenanceNode | None:
    if breach.canary_id is None:
        return None
    seed = next(
        (
            event
            for event in prior
            if event.event_type is TraceEventType.CANARY_SEEDED
            and event.payload.get("canary_id") == breach.canary_id
        ),
        None,
    )
    if seed is None:
        return None
    detail: dict[str, Any] = {"source_location": seed.payload.get("source_location")}
    value = seed.payload.get("full_value", seed.payload.get("value"))
    if isinstance(value, str) and value:
        read = next(
            (
                event
                for event in prior
                if event.seq > seed.seq
                and event.event_type is TraceEventType.TOOL_RESPONSE
                and value in json.dumps(event.payload, ensure_ascii=False)
            ),
            None,
        )
        if read is not None:
            detail.update(
                read_event_seq=read.seq, read_turn_index=read.turn_index, read_tool=read.tool_name
            )
    return ProvenanceNode(
        stage="origin",
        event_seq=seed.seq,
        turn_index=seed.turn_index,
        summary="Canary seeded",
        detail=detail,
    )


def _injection(breach: DetectedBreach, prior: list[TraceEvent]) -> ProvenanceNode | None:
    carriers = [
        event
        for event in prior
        if event.event_type in _UNTRUSTED_CARRIERS
        and event.payload.get("contains_untrusted_content") is True
    ]
    if not carriers:
        return None
    memory_read_seq = breach.evidence.get("memory_read_event_seq")
    memory = next((event for event in carriers if event.seq == memory_read_seq), None)
    event = memory or carriers[-1]
    detail = {
        "tool_name": event.tool_name,
        "event_type": event.event_type.value,
        "untrusted_source_id": event.payload.get("untrusted_source_id"),
    }
    if memory is not None:
        detail.update(
            {
                key: breach.evidence[key]
                for key in (
                    "origin_session_id",
                    "original_untrusted_source_id",
                    "origin_input_event_seq",
                    "memory_write_event_seq",
                )
                if key in breach.evidence
            }
        )
    return ProvenanceNode(
        stage="injection_vector",
        event_seq=event.seq,
        turn_index=event.turn_index,
        summary="Untrusted input from trial memory" if memory else "Most recent untrusted input",
        detail=detail,
    )


def _scope(event: TraceEvent) -> tuple[str, str, int]:
    return event.run_id, event.scenario_id, event.trial_index


class ProvenanceBuilder:
    @staticmethod
    def build_all(
        breaches: Sequence[DetectedBreach], events: Sequence[TraceEvent], scenario: ScenarioSpec
    ) -> list[BreachProvenance]:
        ordered = sorted(events, key=lambda event: event.seq)
        by_seq = {event.seq: event for event in ordered}
        results: list[BreachProvenance] = []
        for breach in breaches:
            sink = by_seq.get(breach.event_seq)
            prior = [
                event
                for event in ordered
                if event.seq < breach.event_seq and (sink is None or _scope(event) == _scope(sink))
            ]
            injection = _injection(breach, prior)
            nodes = [node for node in (_origin(breach, prior), injection) if node is not None]
            turn = next(
                (
                    event
                    for event in reversed(prior)
                    if event.actor == "agent"
                    and event.turn_index == breach.turn_index
                    and event.event_type in _AGENT_EVENTS
                    and (sink is None or event.session_id == sink.session_id)
                    and (injection is None or event.seq > injection.event_seq)
                ),
                sink,
            )
            nodes.extend(
                [
                    ProvenanceNode(
                        stage="agent_turn",
                        event_seq=turn.seq if turn else breach.event_seq,
                        turn_index=breach.turn_index,
                        summary="Agent turn at the breach",
                        detail={"session_id": turn.session_id, "tool_name": turn.tool_name}
                        if turn
                        else {},
                    ),
                    ProvenanceNode(
                        stage="breach_sink",
                        event_seq=breach.event_seq,
                        turn_index=breach.turn_index,
                        summary=breach.summary,
                        detail={
                            "tool_name": breach.sink_tool,
                            "event_type": sink.event_type.value if sink else None,
                            **breach.evidence,
                        },
                    ),
                ]
            )
            results.append(
                BreachProvenance(
                    breach_id=breach.breach_id,
                    owasp_category=breach.owasp_category.value,
                    severity=breach.severity.value,
                    breach_kind=breach.breach_kind,
                    canary_id=breach.canary_id,
                    transform_used=breach.transform_used,
                    sink_tool=breach.sink_tool,
                    nodes=nodes,
                    remediation_hint=scenario.assertions.remediation_hint,
                )
            )
        return results
