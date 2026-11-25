"""Tool contracts, routing, and trace binding for synthetic environments."""

from collections.abc import Callable, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from ..core.errors import ConfigurationError
from ..core.trace import TraceEventType, TraceWriter


class ToolSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    description: str
    input_schema: dict[str, Any]
    is_sink: bool = False
    trust_zone: Literal["internal_trusted", "internal_restricted", "external_untrusted"] = (
        "internal_trusted"
    )


class ToolCallResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    structured_data: dict[str, Any] | None = None
    is_error: bool = False
    contains_untrusted_content: bool = False
    untrusted_source_id: str | None = None


class HoneyEnvironment(Protocol):
    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None: ...
    def list_tools(self) -> list[ToolSchema]: ...
    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult: ...
    async def snapshot_state(self) -> dict[str, Any]: ...
    async def teardown(self) -> None: ...


@runtime_checkable
class _ToolCallClassifier(Protocol):
    def classify_tool_call(self, schema: ToolSchema, arguments: dict[str, Any]) -> ToolSchema: ...


class CompositeEnvironment:
    def __init__(self, environments: Sequence[HoneyEnvironment]) -> None:
        self._environments: tuple[HoneyEnvironment, ...] = tuple(environments)
        self._active: list[HoneyEnvironment] = []
        self._tools()

    def _tools(self) -> dict[str, tuple[ToolSchema, HoneyEnvironment]]:
        tools: dict[str, tuple[ToolSchema, HoneyEnvironment]] = {}
        for environment in self._environments:
            for schema in environment.list_tools():
                if schema.name in tools:
                    raise ConfigurationError(f"Duplicate tool name: {schema.name}")
                tools[schema.name] = (schema, environment)
        return tools

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        if self._active:
            raise ConfigurationError("Composite environment is already set up")
        try:
            for environment in self._environments:
                self._active.append(environment)
                await environment.setup(sandbox_dir, rendered_state)
            self._tools()
        except BaseException:
            with suppress(Exception):
                await self.teardown()
            raise

    def list_tools(self) -> list[ToolSchema]:
        return [schema for schema, _ in self._tools().values()]

    def tool_schema_for_call(self, name: str, arguments: dict[str, Any]) -> ToolSchema | None:
        target = self._tools().get(name)
        if target is None:
            return None
        schema, provider = target
        return (
            provider.classify_tool_call(schema, arguments)
            if isinstance(provider, _ToolCallClassifier)
            else schema
        )

    def classify_tool_call(self, schema: ToolSchema, arguments: dict[str, Any]) -> ToolSchema:
        return self.tool_schema_for_call(schema.name, arguments) or schema

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        target = self._tools().get(name)
        if target is None:
            return ToolCallResult(content=f"Unknown tool: {name}", is_error=True)
        return await target[1].call_tool(name, arguments, turn_index)

    async def snapshot_state(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for environment in self._environments:
            state = await environment.snapshot_state()
            if duplicates := sorted(result.keys() & state.keys()):
                raise ConfigurationError(f"Duplicate snapshot keys: {', '.join(duplicates)}")
            result.update(state)
        return result

    async def teardown(self) -> None:
        errors: list[Exception] = []
        while self._active:
            try:
                await self._active.pop().teardown()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise ConfigurationError("Composite environment teardown failed") from ExceptionGroup(
                "Child teardown errors", errors
            )


type TraceCallback = Callable[[TraceEventType, str, int, dict[str, Any]], None]


class TraceBoundEnvironment:
    def __init__(self, on_event: TraceCallback | None = None) -> None:
        self._on_event: TraceCallback | None = on_event

    def bind_trace(self, trace: TraceWriter, session_id: str) -> None:
        def emit(event: TraceEventType, tool: str, turn: int, payload: dict[str, Any]) -> None:
            trace.emit(event, "environment", session_id, turn, tool, payload)

        self._on_event = emit

    def _emit(self, event: TraceEventType, tool: str, turn: int, payload: dict[str, Any]) -> None:
        if self._on_event is not None:
            self._on_event(event, tool, turn, payload)
