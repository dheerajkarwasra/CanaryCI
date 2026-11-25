"""Discover and validate packaged and workspace scenario files."""

from collections.abc import Sequence
from importlib.resources import as_file, files
from pathlib import Path

from ..core.errors import ScenarioValidationError
from ..core.models import ScenarioSpec, load_scenario_yaml

_PACKS: tuple[str, ...] = ("phase1_core", "phase2_persistence", "phase3_multimodal_a2a")


def discover_scenarios(paths: Sequence[str], *, base_dir: Path | None = None) -> list[ScenarioSpec]:
    found: dict[str, ScenarioSpec] = {}

    def add(path: Path) -> None:
        scenario = load_scenario_yaml(path)
        if scenario.id in found:
            raise ScenarioValidationError(f"Duplicate scenario ID: {scenario.id}")
        found[scenario.id] = scenario

    for entry in paths:
        if entry.startswith("builtin:"):
            pack = entry.removeprefix("builtin:")
            if pack != "all" and pack not in _PACKS:
                raise ScenarioValidationError(f"Unknown built-in scenario pack: {pack}")
            for name in _PACKS if pack == "all" else (pack,):
                root = files(__package__).joinpath(name)
                if not root.is_dir():
                    if pack == "all":
                        continue
                    raise ScenarioValidationError(f"Built-in scenario pack is unavailable: {name}")
                for item in sorted(root.iterdir(), key=lambda resource: resource.name):
                    if item.is_file() and item.name.endswith((".yaml", ".yml")):
                        with as_file(item) as path:
                            add(path)
        else:
            path = (base_dir or Path.cwd()) / entry
            if path.is_file():
                add(path)
            elif path.is_dir():
                for candidate in sorted(path.rglob("*")):
                    if candidate.is_file() and candidate.suffix.lower() in {".yaml", ".yml"}:
                        add(candidate)
            else:
                raise ScenarioValidationError(f"Scenario path does not exist: {path}")
    return list(found.values())
