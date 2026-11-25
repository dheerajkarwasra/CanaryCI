"""Create agent adapters from validated CanaryCI configuration."""

from collections.abc import Mapping

import httpx

from ..canary.seeder import GeneratedCanary
from ..core.models import AdapterConfig, ScenarioSpec
from .base import AgentAdapter
from .cli_adapter import CliSubprocessAdapter
from .http_adapter import HttpWebhookAdapter
from .litellm_mcp import LiteLLMMcpAdapter
from .playwright_adapter import PlaywrightBrowserAdapter
from .python_callable import PythonCallableAdapter
from .scripted import ScriptedAgentAdapter

__all__ = ["create_adapter"]


def create_adapter(
    config: AdapterConfig,
    *,
    scenario: ScenarioSpec | None = None,
    canaries: Mapping[str, GeneratedCanary] | None = None,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> AgentAdapter:
    match config.kind:
        case "scripted":
            return ScriptedAgentAdapter(config.mode, scenario=scenario, canaries=canaries)
        case "cli":
            return CliSubprocessAdapter(config.command or (), config.pass_env)
        case "http":
            return HttpWebhookAdapter(config.endpoint_url or "", http_transport)
        case "python":
            return PythonCallableAdapter(config.callable_path or "")
        case "litellm":
            return LiteLLMMcpAdapter(config)
        case "playwright":
            return PlaywrightBrowserAdapter(config)
