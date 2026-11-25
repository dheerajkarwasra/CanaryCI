from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from canary_ci.core.errors import CanaryCIError, ConfigurationError, ScenarioValidationError
from canary_ci.core.models import (
    CanaryKind,
    OwaspCategory,
    ScenarioTier,
    Severity,
    TrustZone,
    load_config_yaml,
    load_mock_profile_yaml,
    load_scenario_yaml,
)

CONFIG = """\
version: "1"
adapter:
  kind: scripted
policy:
  waivers:
    - scenario_id: test-scenario
      owner: QA
      reason: Approved fixture waiver
      expires_at: 2027-01-01
"""
SCENARIO = """\
api_version: canary-ci/v1
id: test-scenario
title: Example scenario
owasp_category: ASI01
severity: high
canaries:
  - id: fixture_data
    kind: data
    format_preset: pii_email
sessions:
  - id: initial
    user_prompt: Summarize the fixture.
assertions: {}
"""
PROFILE = """\
api_version: canary-ci/mock-v1
profile_id: test-profile
tools:
  - name: lookup
    description: Read a fixture.
    input_schema: {type: object}
    default_response: Fixture result
"""


def write_yaml(tmp_path: Path, contents: str) -> Path:
    path = tmp_path / "fixture.yaml"
    path.write_text(contents, encoding="utf-8")
    return path


def test_load_config(tmp_path: Path) -> None:
    config = load_config_yaml(write_yaml(tmp_path, CONFIG))

    assert config.seed == "canary-default-seed-v1"
    assert config.concurrency == 4
    assert config.adapter.mode == "benign"
    assert config.policy is not None
    assert config.policy.waivers[0].expires_at == date(2027, 1, 1)


def test_load_scenario(tmp_path: Path) -> None:
    scenario = load_scenario_yaml(write_yaml(tmp_path, SCENARIO))

    assert scenario.id == "test-scenario"
    assert scenario.owasp_category is OwaspCategory.ASI01
    assert scenario.severity is Severity.HIGH
    assert scenario.tier is ScenarioTier.FULL
    assert scenario.canaries[0].kind is CanaryKind.DATA
    assert scenario.sessions[0].user_prompt == "Summarize the fixture."


def test_load_mock_profile(tmp_path: Path) -> None:
    profile = load_mock_profile_yaml(write_yaml(tmp_path, PROFILE))

    assert profile.profile_id == "test-profile"
    assert profile.tools[0].default_response == "Fixture result"
    assert profile.tools[0].trust_zone is TrustZone.INTERNAL_TRUSTED


@pytest.mark.parametrize(
    ("loader", "contents", "error_type", "field_path"),
    [
        (load_config_yaml, CONFIG + "extra: true\n", ConfigurationError, "extra"),
        (load_scenario_yaml, SCENARIO + "extra: true\n", ScenarioValidationError, "extra"),
        (
            load_mock_profile_yaml,
            PROFILE + "    extra: true\n",
            ConfigurationError,
            "tools.0.extra",
        ),
        (
            load_scenario_yaml,
            SCENARIO.replace("ASI01", "ASI99"),
            ScenarioValidationError,
            "owasp_category",
        ),
        (
            load_scenario_yaml,
            SCENARIO.replace("test-scenario", "Bad ID"),
            ScenarioValidationError,
            "id",
        ),
        (
            load_config_yaml,
            CONFIG.replace("kind: scripted", "kind: scripted\n  timeout_seconds: '60'"),
            ConfigurationError,
            "adapter.timeout_seconds",
        ),
        (
            load_scenario_yaml,
            SCENARIO + "description: null\n",
            ScenarioValidationError,
            "description",
        ),
    ],
)
def test_loader_reports_invalid_field(
    tmp_path: Path,
    loader: Callable[[Path], BaseModel],
    contents: str,
    error_type: type[CanaryCIError],
    field_path: str,
) -> None:
    path = write_yaml(tmp_path, contents)

    with pytest.raises(error_type) as caught:
        loader(path)

    assert f"{path}: {field_path}:" in str(caught.value)


def test_unsafe_yaml_reports_file_path(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, "!!python/object:builtins.object {}\n")

    with pytest.raises(ConfigurationError, match="invalid YAML at line 1") as caught:
        load_config_yaml(path)

    assert str(path) in str(caught.value)


def test_invalid_yaml_date_reports_file_path(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, CONFIG.replace("2027-01-01", "2027-02-30"))

    with pytest.raises(ConfigurationError, match="invalid YAML scalar") as caught:
        load_config_yaml(path)

    assert str(path) in str(caught.value)


def test_nested_model_is_frozen(tmp_path: Path) -> None:
    adapter = load_config_yaml(write_yaml(tmp_path, CONFIG)).adapter

    with pytest.raises(ValidationError, match="frozen_instance"):
        adapter.mode = "compromised"
