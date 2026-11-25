"""Serve deterministic custom tools defined by YAML mock profiles."""

from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from ..canary.seeder import CanarySeeder, GeneratedCanary
from ..core.errors import ConfigurationError
from ..core.models import MockProfileSpec, MockToolSpec, load_mock_profile_yaml
from .base import ToolCallResult, ToolSchema


class _MockCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str
    tool_name: str
    arguments: dict[str, Any]
    turn_index: int


def _matches(expected: object, actual: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _matches(value, actual[key]) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(_matches(a, b) for a, b in zip(expected, actual, strict=True))
        )
    return type(expected) is type(actual) and expected == actual


class CustomMockProfileEnvironment:
    def __init__(
        self,
        profiles: Sequence[MockProfileSpec],
        canaries: Mapping[str, GeneratedCanary] | None = None,
    ) -> None:
        self._canaries: Mapping[str, GeneratedCanary] = canaries or {}
        self._tools: dict[str, tuple[str, MockToolSpec]] = {}
        self._rendered: dict[str, tuple[str, MockToolSpec]] = {}
        self._calls: list[_MockCall] = []
        for profile in profiles:
            for tool in profile.tools:
                if tool.name in self._tools:
                    raise ConfigurationError(f"Duplicate custom mock tool: {tool.name}")
                self._tools[tool.name] = (profile.profile_id, tool)

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        self._rendered = {
            name: (
                profile,
                MockToolSpec.model_validate(
                    CanarySeeder.render_template(
                        tool.model_dump(mode="json", exclude_none=True),
                        self._canaries,
                    )
                ),
            )
            for name, (profile, tool) in self._tools.items()
        }
        self._calls.clear()

    def list_tools(self) -> list[ToolSchema]:
        return [
            ToolSchema(
                name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema,
                is_sink=tool.is_sink,
                trust_zone=tool.trust_zone.value,
            )
            for _, tool in (self._rendered or self._tools).values()
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        if name not in self._rendered:
            return ToolCallResult(content=f"Unknown custom mock tool: {name}", is_error=True)
        profile, tool = self._rendered[name]
        self._calls.append(
            _MockCall(
                profile_id=profile,
                tool_name=name,
                arguments=deepcopy(arguments),
                turn_index=turn_index,
            )
        )
        source = f"mock:{profile}:{name}"
        for response in tool.conditional_responses:
            if _matches(response.when_args, arguments):
                return ToolCallResult(
                    content=response.response,
                    contains_untrusted_content=response.contains_untrusted_content,
                    untrusted_source_id=(response.untrusted_source_id or source)
                    if response.contains_untrusted_content
                    else None,
                )
        return ToolCallResult(
            content=tool.default_response,
            contains_untrusted_content=tool.default_untrusted,
            untrusted_source_id=source if tool.default_untrusted else None,
        )

    async def snapshot_state(self) -> dict[str, Any]:
        return {"custom_mock_calls": [call.model_dump(mode="json") for call in self._calls]}

    async def teardown(self) -> None:
        self._rendered.clear()
        self._calls.clear()


def load_custom_profiles(ids: Sequence[str], paths: Sequence[str | Path]) -> list[MockProfileSpec]:
    profiles: dict[str, MockProfileSpec] = {}
    for path in map(Path, paths):
        candidates = (
            sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")) if path.is_dir() else [path]
        )
        for candidate in candidates:
            profile = load_mock_profile_yaml(candidate)
            if profile.profile_id in profiles:
                raise ConfigurationError(f"Duplicate custom mock profile: {profile.profile_id}")
            profiles[profile.profile_id] = profile
    for profile_id in ids:
        if profile_id not in profiles:
            raise ConfigurationError(f"Unknown custom mock profile: {profile_id}")
    return [profiles[profile_id] for profile_id in dict.fromkeys(ids)]
