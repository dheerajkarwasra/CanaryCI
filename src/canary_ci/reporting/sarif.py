"""Export deterministic breach provenance as SARIF 2.1.0."""

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..core.constants import SEVERITY_RANK
from ..core.errors import ConfigurationError
from ..core.models import ScenarioSpec
from ..runner.suite_runner import SuiteRunSummary
from . import _STAGE_LABELS

_SEVERITIES: dict[str, str] = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
_LEVELS: dict[str, str] = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


class SarifLog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_url: str = Field(
        default="https://json.schemastore.org/sarif-2.1.0.json", alias="$schema"
    )
    version: Literal["2.1.0"] = "2.1.0"
    runs: list[dict[str, Any]]


def _rule(scenario: ScenarioSpec) -> dict[str, Any]:
    help_text = (
        f"{scenario.description or scenario.title}\n\n"
        f"**Remediation:** {scenario.assertions.remediation_hint}"
    )
    return {
        "id": scenario.id,
        "name": "".join(word.capitalize() for word in re.split("[-_]", scenario.id)),
        "shortDescription": {"text": scenario.title},
        "help": {"text": scenario.assertions.remediation_hint, "markdown": help_text},
        "properties": {
            "tags": [
                "security",
                scenario.owasp_category.value,
                *(scenario.compliance.cwe if scenario.compliance else []),
            ],
            "security-severity": _SEVERITIES[scenario.severity],
        },
    }


class SarifExporter:
    @staticmethod
    def generate_sarif_dict(
        summary: SuiteRunSummary,
        scenarios: Sequence[ScenarioSpec],
        target_artifact_uri: str = "canary.yaml",
    ) -> dict[str, Any]:
        specs = {scenario.id: scenario for scenario in scenarios}
        physical_location = {
            "artifactLocation": {"uri": target_artifact_uri},
            "region": {"startLine": 1},
        }
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        for outcome in summary.outcomes:
            if outcome.scenario_id not in specs:
                raise ConfigurationError(
                    f"Missing scenario metadata for SARIF: {outcome.scenario_id}"
                )
            rule_index = len(rules)
            rules.append(_rule(specs[outcome.scenario_id]))
            if outcome.waived:
                continue
            breaches = [breach for trial in outcome.trials for breach in trial.breaches]
            if not breaches:
                continue
            primary = max(breaches, key=lambda breach: SEVERITY_RANK[breach.severity])
            details = ", ".join(
                value
                for value in (
                    primary.canary_id,
                    primary.transform_used,
                    primary.sink_tool,
                )
                if value
            )
            message = f"{primary.summary} ({details})" if details else primary.summary
            result: dict[str, Any] = {
                "ruleId": outcome.scenario_id,
                "ruleIndex": rule_index,
                "level": _LEVELS[primary.severity],
                "message": {"text": message},
                "locations": [{"physicalLocation": physical_location}],
            }
            flows: list[dict[str, Any]] = []
            for trial in outcome.trials:
                for chain in trial.provenance_chains:
                    if not chain.nodes:
                        continue
                    locations = [
                        {
                            "location": {
                                "physicalLocation": physical_location,
                                "message": {
                                    "text": f"{_STAGE_LABELS[node.stage]} · {node.summary}"
                                },
                            },
                            "executionOrder": index,
                        }
                        for index, node in enumerate(chain.nodes, start=1)
                    ]
                    flows.append({"threadFlows": [{"locations": locations}]})
            if flows:
                result["codeFlows"] = flows
            results.append(result)
        return SarifLog(
            runs=[
                {
                    "tool": {
                        "driver": {
                            "name": "CanaryCI",
                            "informationUri": "https://github.com/canary-ci/canary-ci",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ]
        ).model_dump(mode="json", by_alias=True)

    @staticmethod
    def write_sarif(
        path: Path,
        summary: SuiteRunSummary,
        scenarios: Sequence[ScenarioSpec],
        target_artifact_uri: str = "canary.yaml",
    ) -> None:
        payload = SarifExporter.generate_sarif_dict(summary, scenarios, target_artifact_uri)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            raise ConfigurationError(f"Cannot write SARIF report at {path}") from exc
