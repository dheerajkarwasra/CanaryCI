"""Schema-backed models and safe YAML loaders."""

import re
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    ValidationError,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema
from yaml.error import MarkedYAMLError

from .constants import DEFAULT_SEED
from .errors import CanaryCIError, ConfigurationError, ScenarioValidationError


class OwaspCategory(StrEnum):
    ASI01 = "ASI01"
    ASI02 = "ASI02"
    ASI03 = "ASI03"
    ASI04 = "ASI04"
    ASI05 = "ASI05"
    ASI06 = "ASI06"
    ASI07 = "ASI07"
    ASI08 = "ASI08"
    ASI09 = "ASI09"
    ASI10 = "ASI10"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScenarioTier(StrEnum):
    SMOKE = "smoke"
    FULL = "full"
    NIGHTLY = "nightly"


class CanaryKind(StrEnum):
    SECRET = "secret"  # noqa: S105 - Schema enum label.
    DATA = "data"


class CanaryPreset(StrEnum):
    API_KEY_STRIPE = "api_key_stripe"
    AWS_ACCESS_KEY = "aws_access_key"
    BEARER_JWT = "bearer_jwt"
    ENV_TOKEN = "env_token"  # noqa: S105 - Schema enum label.
    PII_EMAIL = "pii_email"
    PII_SSN_TAGGED = "pii_ssn_tagged"
    CONFIDENTIAL_CODE = "confidential_code"


class TrustZone(StrEnum):
    INTERNAL_TRUSTED = "internal_trusted"
    INTERNAL_RESTRICTED = "internal_restricted"
    EXTERNAL_UNTRUSTED = "external_untrusted"


class ArgumentOperator(StrEnum):
    EQUALS = "equals"
    CONTAINS = "contains"
    REGEX = "regex"
    GLOB = "glob"
    PATH_OUTSIDE_WORKSPACE = "path_outside_workspace"
    SQL_DESTRUCTIVE = "sql_destructive"
    NUMERIC_GT = "numeric_gt"
    NUMERIC_LT = "numeric_lt"
    DOMAIN_NOT_IN_ALLOWLIST = "domain_not_in_allowlist"


def _reject_null(value: object) -> object:
    if value is None:
        raise ValueError("Omit this field instead of setting it to null")
    return value


def _normalize_integer(value: object) -> object:
    # JSON Schema integers include numbers such as 1.0 with no fractional part.
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _validate_date(value: object) -> object:
    if type(value) is date or (
        isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value)
    ):
        return value
    raise ValueError("Expected an ISO-8601 date (YYYY-MM-DD)")


type _Omittable[T] = Annotated[T | SkipJsonSchema[None], BeforeValidator(_reject_null)]
type _JsonObject = dict[str, JsonValue]

_Integer = Annotated[StrictInt, BeforeValidator(_normalize_integer)]
_Number = Annotated[float, Field(strict=True, allow_inf_nan=False)]
_Date = Annotated[date, BeforeValidator(_validate_date)]


class _SchemaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WaiverSpec(_SchemaModel):
    scenario_id: str
    owner: str
    reason: str = Field(min_length=10)
    expires_at: _Date


class PolicyConfig(_SchemaModel):
    fail_on_severity: Severity = Severity.LOW
    max_breach_rate: _Number = Field(default=0.0, ge=0.0, le=1.0)
    fail_on_new_regressions_only: StrictBool = False
    waivers: list[WaiverSpec] = Field(default_factory=list)


class AdapterConfig(_SchemaModel):
    kind: Literal["scripted", "litellm", "http", "cli", "python", "playwright"]
    mode: Literal["benign", "compromised"] = "benign"
    model: _Omittable[str] = None
    system_prompt: _Omittable[str] = None
    system_prompt_file: _Omittable[str] = None
    temperature: _Number = Field(default=0.0, ge=0.0, le=2.0)
    endpoint_url: _Omittable[str] = None
    command: _Omittable[list[str]] = None
    pass_env: list[str] = Field(default_factory=list)
    callable_path: _Omittable[str] = None
    timeout_seconds: _Number = Field(default=60.0, ge=1.0, le=600.0)


class DefenseProxyConfig(_SchemaModel):
    kind: Literal["webhook_policy", "mcp_command_wrapper"]
    policy_url: _Omittable[str] = None
    command: _Omittable[list[str]] = None
    fail_closed: StrictBool = True


class CanaryConfig(_SchemaModel):
    version: Literal["1"]
    project_name: str = "default-agent"
    seed: str = DEFAULT_SEED
    concurrency: _Integer = Field(default=4, ge=1, le=64)
    trials: _Integer = Field(default=1, ge=1, le=100)
    artifacts_dir: str = ".canary"
    scenario_paths: list[str] = Field(default_factory=lambda: ["builtin:phase1_core"])
    mock_profile_paths: list[str] = Field(default_factory=list)
    include_tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=list)
    adapter: AdapterConfig
    defense_proxy: _Omittable[DefenseProxyConfig] = None
    policy: _Omittable[PolicyConfig] = None


class ComplianceSpec(_SchemaModel):
    cwe: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    eu_ai_act: list[str] = Field(default_factory=list)


class LimitsSpec(_SchemaModel):
    max_turns: _Integer = Field(default=15, ge=1)
    max_tool_calls: _Integer = Field(default=25, ge=1)
    max_identical_calls: _Integer = Field(default=4, ge=2)
    timeout_seconds: _Number = Field(default=60.0, ge=1.0)


class CanarySpec(_SchemaModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_]+$")
    kind: CanaryKind
    format_preset: CanaryPreset
    description: _Omittable[str] = None
    allowed_sinks: list[str] = Field(default_factory=list)


class FileSpec(_SchemaModel):
    path: str
    content: str
    trust_level: Literal["trusted", "untrusted"] = "trusted"
    protected: StrictBool = False


class DatabaseSpec(_SchemaModel):
    schema_sql: _Omittable[str] = None
    seed_rows: _Omittable[_JsonObject] = None


class RugPullSpec(_SchemaModel):
    tool_name: str
    trigger_after_calls: _Integer = Field(ge=1)
    mutated_description: _Omittable[str] = None
    mutated_input_schema: _Omittable[_JsonObject] = None
    injected_response_suffix: _Omittable[str] = None


class EnvironmentSpec(_SchemaModel):
    env_vars: dict[str, str] = Field(default_factory=dict)
    files: list[FileSpec] = Field(default_factory=list)
    emails: list[_JsonObject] = Field(default_factory=list)
    pull_requests: list[_JsonObject] = Field(default_factory=list)
    issues: list[_JsonObject] = Field(default_factory=list)
    tickets: list[_JsonObject] = Field(default_factory=list)
    wiki_docs: list[_JsonObject] = Field(default_factory=list)
    database: _Omittable[DatabaseSpec] = None
    mock_urls: list[_JsonObject] = Field(default_factory=list)
    internal_domains: list[str] = Field(default_factory=lambda: ["corp.internal"])
    enable_persistent_memory: StrictBool = False
    custom_mock_profiles: list[str] = Field(default_factory=list)
    tool_overrides: list[_JsonObject] = Field(default_factory=list)
    rug_pulls: list[RugPullSpec] = Field(default_factory=list)
    a2a_peers: list[_JsonObject] = Field(default_factory=list)
    browser_pages: list[_JsonObject] = Field(default_factory=list)


class SessionSpec(_SchemaModel):
    id: str
    user_prompt: str
    system_prompt_hint: _Omittable[str] = None
    additional_files: list[_JsonObject] = Field(default_factory=list)


class ArgumentRuleSpec(_SchemaModel):
    arg: str
    operator: ArgumentOperator
    value: JsonValue = None


class TripwireSpec(_SchemaModel):
    id: str
    description: str
    forbidden_tool: _Omittable[str] = None
    tool: _Omittable[str] = None
    argument_rules: list[ArgumentRuleSpec] = Field(default_factory=list)


class ApprovalPolicySpec(_SchemaModel):
    tool_name: str
    must_disclose_fields: list[str]
    max_summary_chars: _Integer = 600


class TaskCompletionSpec(_SchemaModel):
    model_config = ConfigDict(allow_inf_nan=False)

    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    path: list[str | Annotated[_Integer, Field(ge=0)]] = Field(min_length=1)
    equals: JsonValue
    session_id: _Omittable[Annotated[str, Field(min_length=1)]] = None


class AssertionsSpec(_SchemaModel):
    task_completion: list[TaskCompletionSpec] = Field(default_factory=list)
    forbid_canary_leak_in_agent_response: StrictBool = False
    tripwires: list[TripwireSpec] = Field(default_factory=list)
    approval_policies: list[ApprovalPolicySpec] = Field(default_factory=list)
    forbid_poisoned_memory_persistence: StrictBool = False
    remediation_hint: str = (
        "Enforce strict privilege separation between untrusted data ingestion "
        "and external egress sinks."
    )


class ScriptedReplaySpec(_SchemaModel):
    benign_steps: list[_JsonObject] = Field(default_factory=list)
    compromised_steps: list[_JsonObject] = Field(default_factory=list)


class ScenarioSpec(_SchemaModel):
    api_version: Literal["canary-ci/v1"]
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{3,63}$")
    title: str = Field(min_length=5)
    description: _Omittable[str] = None
    owasp_category: OwaspCategory
    severity: Severity
    tier: ScenarioTier = ScenarioTier.FULL
    tags: list[str] = Field(default_factory=list)
    compliance: _Omittable[ComplianceSpec] = None
    limits: _Omittable[LimitsSpec] = None
    trials: _Omittable[Annotated[_Integer, Field(ge=1, le=100)]] = None
    canaries: list[CanarySpec] = Field(default_factory=list)
    environment: _Omittable[EnvironmentSpec] = None
    sessions: list[SessionSpec] = Field(min_length=1)
    assertions: AssertionsSpec
    scripted_replay: _Omittable[ScriptedReplaySpec] = None

    @model_validator(mode="after")
    def validate_task_checks(self) -> Self:
        seen: set[str] = set()
        sessions = [session.id for session in self.sessions]
        for check in self.assertions.task_completion:
            if check.id in seen:
                raise ValueError(f"Duplicate task-completion assertion: {check.id}")
            seen.add(check.id)
            session_id = check.session_id if check.session_id is not None else sessions[-1]
            if sessions.count(session_id) != 1:
                raise ValueError(
                    f"Task-completion assertion requires one matching session: {session_id}"
                )
        return self


class ConditionalResponseSpec(_SchemaModel):
    when_args: _JsonObject
    response: str
    contains_untrusted_content: StrictBool = False
    untrusted_source_id: _Omittable[str] = None


class MockToolSpec(_SchemaModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    description: str
    input_schema: _JsonObject
    is_sink: StrictBool = False
    trust_zone: TrustZone = TrustZone.INTERNAL_TRUSTED
    conditional_responses: list[ConditionalResponseSpec] = Field(default_factory=list)
    default_response: str
    default_untrusted: StrictBool = False


class MockProfileSpec(_SchemaModel):
    api_version: Literal["canary-ci/mock-v1"]
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,63}$")
    description: _Omittable[str] = None
    tools: list[MockToolSpec] = Field(min_length=1)


def _load_yaml[ModelT: _SchemaModel](
    path: Path, model: type[ModelT], error_type: type[CanaryCIError]
) -> ModelT:
    try:
        with path.open(encoding="utf-8") as source:
            data = yaml.safe_load(source)
    except OSError as exc:
        raise error_type(f"{path}: {exc.strerror}") from exc
    except UnicodeError:
        raise error_type(f"{path}: expected UTF-8 YAML") from None
    except yaml.YAMLError as exc:
        mark = exc.problem_mark if isinstance(exc, MarkedYAMLError) else None
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise error_type(f"{path}: invalid YAML{location}") from None
    except (ValueError, OverflowError):
        raise error_type(f"{path}: <root>: invalid YAML scalar") from None

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        details = []
        for error in exc.errors(include_url=False, include_context=False, include_input=False):
            field_path = ".".join(map(str, error["loc"])) or "<root>"
            details.append(f"{path}: {field_path}: {error['msg']}")
        raise error_type("\n".join(details)) from None


def load_config_yaml(path: Path) -> CanaryConfig:
    return _load_yaml(path, CanaryConfig, ConfigurationError)


def load_scenario_yaml(path: Path) -> ScenarioSpec:
    return _load_yaml(path, ScenarioSpec, ScenarioValidationError)


def load_mock_profile_yaml(path: Path) -> MockProfileSpec:
    return _load_yaml(path, MockProfileSpec, ConfigurationError)
