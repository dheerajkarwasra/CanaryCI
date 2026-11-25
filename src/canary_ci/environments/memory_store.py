"""Persist synthetic notes and rank RAG chunks across sessions of one trial."""

import math
import re
from collections import Counter
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core.errors import ConfigurationError
from ..core.trace import TraceEventType
from .base import ToolCallResult, ToolSchema, TraceBoundEnvironment

_WORD = re.compile(r"\w+")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _SaveNote(_Model):
    key: str = Field(min_length=1)
    content: str
    tags: list[str] = Field(default_factory=list)


class _ReadNotes(_Model):
    query: str = ""


class _Ingest(_Model):
    title: str = Field(min_length=1)
    text: str


class _Retrieve(_Model):
    query: str
    top_k: int = Field(default=3, ge=1)


class _Entry(_Model):
    key: str
    content: str
    title: str | None = None
    tags: list[str] = Field(default_factory=list)
    tainted_by: str | None = None


class _State(_Model):
    notes: dict[str, _Entry] = Field(default_factory=dict)
    chunks: list[_Entry] = Field(default_factory=list)


class _ReadResult(_Model):
    notes: list[_Entry] = Field(default_factory=list)
    chunks: list[_Entry] = Field(default_factory=list)


_TOOLS: tuple[ToolSchema, ...] = tuple(
    ToolSchema(name=name, description=description, input_schema=model.model_json_schema())
    for name, description, model in (
        ("memory_save_note", "Save a note to this trial's memory", _SaveNote),
        ("memory_read_notes", "Read saved notes from this trial", _ReadNotes),
        ("rag_ingest_document", "Index a document in this trial's RAG store", _Ingest),
        ("rag_retrieve_chunks", "Find relevant chunks in this trial's RAG store", _Retrieve),
    )
)


def _rank(chunks: list[_Entry], query: str, top_k: int) -> list[_Entry]:
    terms = sorted(set(_WORD.findall(query.casefold())))
    if not chunks or not terms:
        return []
    counts = [
        Counter(_WORD.findall(f"{chunk.title or ''} {chunk.content}".casefold()))
        for chunk in chunks
    ]
    document_count = len(counts)
    average_length = sum(sum(words.values()) for words in counts) / document_count
    if not average_length:
        return []
    idf: dict[str, float] = {}
    for term in terms:
        frequency = sum(term in words for words in counts)
        idf[term] = math.log1p((document_count - frequency + 0.5) / (frequency + 0.5))
    scores: list[tuple[float, int]] = []
    for index, words in enumerate(counts):
        length_factor = 1.2 * (0.25 + 0.75 * sum(words.values()) / average_length)
        score = sum(idf[term] * 2.2 * words[term] / (words[term] + length_factor) for term in terms)
        if score > 0:
            scores.append((-score, index))
    return [chunks[index] for _, index in sorted(scores)[:top_k]]


class PersistentMemoryEnvironment(TraceBoundEnvironment):
    def __init__(self, trial_root: Path | None = None) -> None:
        super().__init__()
        self._trial_root: Path | None = trial_root
        self._path: Path | None = None
        self._state: _State = _State()
        self.session_tainted_by_source_id: str | None = None

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        self._path = (self._trial_root or sandbox_dir) / "persistent_memory.json"
        self.session_tainted_by_source_id = None
        self._state = _State()
        try:
            self._state = _State.model_validate_json(self._path.read_bytes())
        except FileNotFoundError:
            return
        except (OSError, ValidationError) as exc:
            raise ConfigurationError("Cannot load the trial's memory store") from exc

    def list_tools(self) -> list[ToolSchema]:
        return list(_TOOLS)

    def _save(self, state: _State) -> None:
        if self._path is None:
            raise ConfigurationError("Persistent memory is unavailable before session setup")
        temp_path: Path | None = None
        try:
            with NamedTemporaryFile(
                dir=self._path.parent, mode="w", encoding="utf-8", delete=False
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(state.model_dump_json())
            temp_path.replace(self._path)
        except OSError as exc:
            raise ConfigurationError("Cannot save the trial's memory store") from exc
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        self._state = state

    def _mutation(self, tool: str, entry: _Entry, turn_index: int) -> None:
        self._emit(
            TraceEventType.MEMORY_MUTATED,
            tool,
            turn_index,
            {
                "key": entry.key,
                "content": entry.content,
                "tainted": entry.tainted_by is not None,
                "source_id": entry.tainted_by,
            },
        )

    @staticmethod
    def _read(entries: list[_Entry], *, chunks: bool = False) -> ToolCallResult:
        tainted = next((entry for entry in entries if entry.tainted_by is not None), None)
        source = f"persistent_memory:{tainted.key}<-{tainted.tainted_by}" if tainted else None
        payload = _ReadResult(chunks=entries) if chunks else _ReadResult(notes=entries)
        return ToolCallResult(
            content=payload.model_dump_json(exclude_unset=True),
            structured_data=payload.model_dump(mode="json", exclude_unset=True),
            contains_untrusted_content=source is not None,
            untrusted_source_id=source,
        )

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        try:
            match name:
                case "memory_save_note":
                    note = _SaveNote.model_validate(arguments)
                    entry = _Entry(
                        key=note.key,
                        content=note.content,
                        tags=note.tags,
                        tainted_by=self.session_tainted_by_source_id,
                    )
                    self._save(
                        _State(
                            notes={**self._state.notes, entry.key: entry}, chunks=self._state.chunks
                        )
                    )
                    self._mutation(name, entry, turn_index)
                    return ToolCallResult(content="Saved note")
                case "memory_read_notes":
                    query = _ReadNotes.model_validate(arguments).query.casefold()
                    notes = [
                        entry
                        for key, entry in sorted(self._state.notes.items())
                        if query in " ".join([key, entry.content, *entry.tags]).casefold()
                    ]
                    return self._read(notes)
                case "rag_ingest_document":
                    document = _Ingest.model_validate(arguments)
                    paragraphs = [
                        line.strip() for line in document.text.split("\n\n") if line.strip()
                    ]
                    chunks = [
                        paragraph[offset : offset + 400]
                        for paragraph in paragraphs
                        for offset in range(0, max(1, len(paragraph) - 49), 350)
                    ]
                    entries = [
                        _Entry(
                            key=f"{document.title}:{index}",
                            title=document.title,
                            content=chunk,
                            tainted_by=self.session_tainted_by_source_id,
                        )
                        for index, chunk in enumerate(chunks)
                    ]
                    existing = [
                        chunk for chunk in self._state.chunks if chunk.title != document.title
                    ]
                    self._save(_State(notes=self._state.notes, chunks=[*existing, *entries]))
                    for entry in entries:
                        self._mutation(name, entry, turn_index)
                    return ToolCallResult(content=f"Indexed {len(entries)} chunks")
                case "rag_retrieve_chunks":
                    retrieve = _Retrieve.model_validate(arguments)
                    return self._read(
                        _rank(self._state.chunks, retrieve.query, retrieve.top_k), chunks=True
                    )
        except ValidationError:
            return ToolCallResult(content=f"Invalid arguments for {name}", is_error=True)
        return ToolCallResult(content=f"Unknown memory tool: {name}", is_error=True)

    async def snapshot_state(self) -> dict[str, Any]:
        return {"persistent_memory": self._state.model_dump(mode="json")}

    async def teardown(self) -> None:
        self._path = None
        self._state = _State()
        self.session_tainted_by_source_id = None
