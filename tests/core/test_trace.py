import json
from pathlib import Path

import pytest

from canary_ci.core.errors import ConfigurationError
from canary_ci.core.trace import TraceEventType, TraceReader, TraceWriter


def test_trace_round_trips_in_sequence(tmp_path: Path) -> None:
    path = tmp_path / "trial.trace.jsonl"
    writer = TraceWriter(path, "run-1", "fixture-scenario", 0)
    event_types = (
        TraceEventType.TRIAL_STARTED,
        TraceEventType.SESSION_STARTED,
        TraceEventType.TRIAL_COMPLETED,
    )

    for event_type in event_types:
        writer.emit(event_type, actor="harness", session_id="first", turn_index=0)

    assert [event.seq for event in writer.events] == [0, 1, 2]
    assert tuple(event.event_type for event in writer.events) == event_types
    assert TraceReader.read_jsonl(path) == writer.events
    assert len(path.read_text(encoding="utf-8").splitlines()) == 3


def test_trace_redacts_nested_host_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_key = "sk-real-secret-key-12345"
    explicit_secret = "local-secret"
    synthetic_canary = "canary_fixture_abc123"
    monkeypatch.setenv("OPENAI_API_KEY", host_key)
    monkeypatch.setenv("AWS_SHORT_FIXTURE", "short")
    path = tmp_path / "trial.trace.jsonl"
    writer = TraceWriter(path, "run-1", "fixture-scenario", 0, (explicit_secret,))
    payload = {
        "items": [
            {"text": f"Key: {host_key}"},
            [explicit_secret, synthetic_canary, "short"],
        ],
        f"key-{host_key}": "redact the key too",
    }

    event = writer.emit(
        TraceEventType.TOOL_RESPONSE,
        actor="environment",
        session_id="first",
        turn_index=1,
        tool_name="lookup",
        payload=payload,
    )

    expected = {
        "items": [
            {"text": "Key: [REDACTED_HOST_CREDENTIAL]"},
            ["[REDACTED_HOST_CREDENTIAL]", synthetic_canary, "short"],
        ],
        "key-[REDACTED_HOST_CREDENTIAL]": "redact the key too",
    }
    raw_trace = path.read_text(encoding="utf-8")
    assert host_key not in raw_trace
    assert explicit_secret not in raw_trace
    assert json.loads(raw_trace)["payload"] == expected
    assert event.payload == expected
    assert writer.events == [event]
    assert payload["items"][0] == {"text": f"Key: {host_key}"}


def test_trace_reader_reports_invalid_line(tmp_path: Path) -> None:
    path = tmp_path / "trial.trace.jsonl"
    writer = TraceWriter(path, "run-1", "fixture-scenario", 0)
    writer.emit(TraceEventType.TRIAL_STARTED, actor="harness", session_id="first", turn_index=0)
    with path.open("a", encoding="utf-8") as file:
        file.write("{}\n")

    with pytest.raises(ConfigurationError) as caught:
        TraceReader.read_jsonl(path)

    assert f"{path}:2:" in str(caught.value)


def test_trace_redacts_colliding_keys_without_dropping_payload(tmp_path: Path) -> None:
    path = tmp_path / "trial.trace.jsonl"
    writer = TraceWriter(path, "run-1", "fixture-scenario", 0, ("local-secret",))
    marker = "[REDACTED_HOST_CREDENTIAL]"
    writer.emit(
        TraceEventType.TOOL_RESPONSE,
        actor="environment",
        session_id="first",
        turn_index=0,
        payload={"local-secret": "canary_fixture_abc123", marker: "original entry"},
    )

    assert TraceReader.read_jsonl(path)[0].payload == {
        f"{marker} (2)": "canary_fixture_abc123",
        marker: "original entry",
    }
