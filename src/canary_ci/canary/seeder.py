"""Derive trial-scoped synthetic canaries and render their templates."""

import base64
import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from typing import Any, assert_never

from pydantic import BaseModel, ConfigDict

from ..core.errors import UnknownCanaryReferenceError
from ..core.models import CanaryKind, CanaryPreset, CanarySpec

_REFERENCE = re.compile(r"\{\{canary\.([^{}]+)\}\}")


class GeneratedCanary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    kind: CanaryKind
    format_preset: CanaryPreset
    full_value: str
    core_token: str
    allowed_sinks: tuple[str, ...]


def _format_canary(preset: CanaryPreset, digest: str) -> tuple[str, str]:
    core = digest[:24]
    tag = core[:12]
    match preset:
        case CanaryPreset.API_KEY_STRIPE:
            return f"sk_live_cnry_{core}", core
        case CanaryPreset.AWS_ACCESS_KEY:
            core = f"CNRY{tag.upper()}"
            return f"AKIA{core}", core
        case CanaryPreset.BEARER_JWT:
            body = base64.urlsafe_b64encode(f"cnry_{tag}".encode()).decode().rstrip("=")
            return f"eyJhbGciOiJIUzI1NiJ9.{body}.sig_{core[12:18]}", core
        case CanaryPreset.ENV_TOKEN:
            return f"CNRY_SEC_{core}", core
        case CanaryPreset.PII_EMAIL:
            return f"patient.{tag}@records.corp.internal", tag
        case CanaryPreset.PII_SSN_TAGGED:
            group = int(digest[:8], 16) % 100
            serial = int(digest[8:16], 16) % 10_000
            core = f"REC-{tag}"
            return f"999-{group:02d}-{serial:04d} [{core}]", core
        case CanaryPreset.CONFIDENTIAL_CODE:
            core = digest[:16]
            return f"PROJECT-NIGHTFALL-{core}", core
    assert_never(preset)


class CanarySeeder:
    @staticmethod
    def generate_all(
        specs: Sequence[CanarySpec], run_seed: str, scenario_id: str, trial_index: int
    ) -> dict[str, GeneratedCanary]:
        canaries: dict[str, GeneratedCanary] = {}
        key = run_seed.encode("utf-8")
        for spec in specs:
            scope = f"canary-ci:v1:{scenario_id}:{trial_index}:{spec.id}".encode()
            digest = hmac.new(key, scope, hashlib.sha256).hexdigest()
            full_value, core_token = _format_canary(spec.format_preset, digest)
            canaries[spec.id] = GeneratedCanary(
                id=spec.id,
                kind=spec.kind,
                format_preset=spec.format_preset,
                full_value=full_value,
                core_token=core_token,
                allowed_sinks=tuple(spec.allowed_sinks),
            )
        return canaries

    @classmethod
    def render_template(cls, value: Any, canaries: Mapping[str, GeneratedCanary]) -> Any:
        if isinstance(value, str):

            def replace(match: re.Match[str]) -> str:
                canary_id = match[1]
                try:
                    return canaries[canary_id].full_value
                except KeyError:
                    raise UnknownCanaryReferenceError(
                        f"Unknown canary reference: {canary_id}"
                    ) from None

            return _REFERENCE.sub(replace, value)
        if isinstance(value, list):
            return [cls.render_template(item, canaries) for item in value]
        if isinstance(value, dict):
            return {key: cls.render_template(item, canaries) for key, item in value.items()}
        return value
