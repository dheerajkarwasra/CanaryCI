"""Execute a scenario trial in an isolated synthetic environment."""

import asyncio
import hashlib
import tempfile
from collections.abc import Mapping
from contextlib import AsyncExitStack
from pathlib import Path
from time import perf_counter
from typing import Any, Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..adapters import create_adapter
from ..adapters.base import AdapterSessionResult, AgentAdapter, SessionExecutionContext
from ..adapters.proxy_gateway import DefenseProxyWrapper
from ..canary.detector import BreachDetector, DetectedBreach
from ..canary.provenance import BreachProvenance, ProvenanceBuilder
from ..canary.seeder import CanarySeeder, GeneratedCanary
from ..core.errors import AdapterExecutionError, ConfigurationError
from ..core.models import CanaryConfig, EnvironmentSpec, LimitsSpec, ScenarioSpec, SessionSpec
from ..core.trace import TraceEventType, TraceWriter
from ..environments.a2a_mock import A2ADelegationEnvironment
from ..environments.base import CompositeEnvironment, ToolCallResult, ToolSchema
from ..environments.browser_dom_server import BrowserDomTrapEnvironment
from ..environments.enterprise_mocks import build_composite_environment
from ..environments.mcp_server import EphemeralMCPServer
from ..environments.memory_store import PersistentMemoryEnvironment
from .task_completion import TaskObservation, failed_task_checks, observe_task_state


class TrialResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    scenario_id: str
    trial_index: int
    passed: bool
    task_completed: bool | None = None
    task_failures: list[str] = Field(default_factory=list)
    mitigated_by: Literal["agent", "defense_proxy"] | None
    breaches: list[DetectedBreach]
    provenance_chains: list[BreachProvenance]
    trace_path: Path
    duration_ms: float
    turns_used: int
    tool_calls_made: int
    token_usage: dict[str, int]


class _TrialMCPServer(EphemeralMCPServer):
    def __init__(
        self,
        environment: CompositeEnvironment,
        spec: EnvironmentSpec,
        trace: TraceWriter,
        session_id: str,
        record_calls: bool,
        memory: PersistentMemoryEnvironment | None = None,
    ) -> None:
        super().__init__(environment, spec, trace=trace, session_id=session_id)
        self._trace: TraceWriter = trace
        self._session_id: str = session_id
        self._record_calls: bool = record_calls
        self._memory: PersistentMemoryEnvironment | None = memory
        self._schemas: dict[str, ToolSchema] = {
            tool.name: tool for tool in environment.list_tools()
        }
        self._next_turn: int = 0

    def list_tools(self, turn_index: int | None = None) -> list[ToolSchema]:
        schemas = super().list_tools(turn_index)
        if self._memory is not None:
            source = self.untrusted_schema_source()
            if source is not None:
                self._memory.session_tainted_by_source_id = source
        return schemas

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        turn_index: int | None = None,
    ) -> ToolCallResult:
        turn = self._next_turn if turn_index is None else turn_index
        self._next_turn = max(self._next_turn, turn + 1)
        if self._record_calls:
            schema = self._schemas.get(name)
            self._trace.emit(
                TraceEventType.TOOL_CALL,
                "agent",
                self._session_id,
                turn,
                name,
                {
                    "arguments": arguments,
                    "is_sink": schema.is_sink if schema else False,
                    "trust_zone": schema.trust_zone if schema else "internal_trusted",
                },
            )
        result = await super().call_tool(name, arguments, turn)
        if self._memory is not None and result.contains_untrusted_content:
            self._memory.session_tainted_by_source_id = result.untrusted_source_id or f"tool:{name}"
        if self._record_calls:
            self._trace.emit(
                TraceEventType.TOOL_RESPONSE,
                "environment",
                self._session_id,
                turn,
                name,
                result.model_dump(),
            )
        return result


class _SessionTools(CompositeEnvironment):
    def __init__(self, environment: CompositeEnvironment, server: EphemeralMCPServer) -> None:
        super().__init__((environment,))
        self._server: EphemeralMCPServer = server

    def list_tools(self) -> list[ToolSchema]:
        return self._server.list_tools()

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        turn_index: int,
    ) -> ToolCallResult:
        return await self._server.call_tool(name, arguments, turn_index)


def _reference_location(scenario: ScenarioSpec, canary_id: str) -> str | None:
    reference = "{{canary." + canary_id + "}}"
    environment = scenario.environment or EnvironmentSpec()
    for name, value in environment.env_vars.items():
        if reference in value:
            return f"env:{name}"
    for file in environment.files:
        if reference in file.content:
            return f"file:{file.path}"
    for session in scenario.sessions:
        for additional_file in session.additional_files:
            if (
                isinstance(path := additional_file.get("path"), str)
                and isinstance(content := additional_file.get("content"), str)
                and reference in content
            ):
                return f"file:{path}"
    return None


def _session_environment(
    scenario: ScenarioSpec,
    session: SessionSpec,
    canaries: Mapping[str, GeneratedCanary],
) -> EnvironmentSpec:
    state = (scenario.environment or EnvironmentSpec()).model_dump(mode="json", exclude_none=True)
    state["files"].extend(session.additional_files)
    try:
        return EnvironmentSpec.model_validate(CanarySeeder.render_template(state, canaries))
    except ValidationError:
        raise ConfigurationError(f"Invalid rendered environment for session {session.id}") from None


def _tool_references(scenario: ScenarioSpec) -> set[str]:
    references = {
        name
        for tripwire in scenario.assertions.tripwires
        for name in (tripwire.tool, tripwire.forbidden_tool)
        if name
    }
    if scenario.scripted_replay is not None:
        for step in (
            scenario.scripted_replay.benign_steps + scenario.scripted_replay.compromised_steps
        ):
            if isinstance(calls := step.get("calls"), list):
                references.update(
                    name
                    for call in calls
                    if isinstance(call, dict) and isinstance(name := call.get("tool"), str)
                )
    return references


class TrialOrchestrator:
    def __init__(self, *, policy_transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._policy_transport: httpx.AsyncBaseTransport | None = policy_transport

    async def execute_trial(
        self,
        scenario: ScenarioSpec,
        config: CanaryConfig,
        run_seed: str,
        trial_index: int,
        *,
        run_id: str | None = None,
        keep_sandbox: bool = False,
    ) -> TrialResult:
        started = perf_counter()
        run_id = run_id if run_id is not None else uuid4().hex
        if not run_id or run_id in {".", ".."} or "/" in run_id or "\\" in run_id:
            raise ConfigurationError("Invalid run ID")
        if trial_index < 0:
            raise ConfigurationError("Trial index must be nonnegative")
        canaries = CanarySeeder.generate_all(scenario.canaries, run_seed, scenario.id, trial_index)
        adapter = create_adapter(config.adapter, scenario=scenario, canaries=canaries)
        trace_path = Path(config.artifacts_dir) / "runs" / run_id / scenario.id
        trace_path /= f"trial_{trial_index}.trace.jsonl"
        try:
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            trace_path.touch(exist_ok=False)
        except OSError as exc:
            raise ConfigurationError(f"Cannot create trial trace at {trace_path}") from exc
        trace = TraceWriter(trace_path, run_id, scenario.id, trial_index)
        with tempfile.TemporaryDirectory(prefix="canary_trial_", delete=not keep_sandbox) as temp:
            return await self._trial_in_sandbox(
                scenario,
                config,
                run_seed,
                Path(temp),
                canaries,
                adapter,
                trace,
                started,
            )

    async def _trial_in_sandbox(
        self,
        scenario: ScenarioSpec,
        config: CanaryConfig,
        run_seed: str,
        sandbox: Path,
        canaries: Mapping[str, GeneratedCanary],
        adapter: AgentAdapter,
        trace: TraceWriter,
        started: float,
    ) -> TrialResult:
        limits = scenario.limits or LimitsSpec()
        first_session = scenario.sessions[0].id
        trace.emit(
            TraceEventType.TRIAL_STARTED,
            "harness",
            first_session,
            0,
            payload={
                "scenario": scenario.model_dump(mode="json", exclude_unset=True),
                "sandbox_dir": str(sandbox),
                "workspace_dir": str(sandbox / "workspace"),
            },
        )
        for canary in canaries.values():
            trace.emit(
                TraceEventType.CANARY_SEEDED,
                "harness",
                first_session,
                0,
                payload={
                    "canary": canary.model_dump(mode="json"),
                    "canary_id": canary.id,
                    "full_value": canary.full_value,
                    "source_location": _reference_location(scenario, canary.id),
                },
            )
        turns = calls = prompt_tokens = completion_tokens = 0
        usage_complete = True
        before: dict[str, str] = {}
        after: dict[str, str] = {}
        observations: dict[str, TaskObservation] = {}
        references = _tool_references(scenario)
        memory = (
            PersistentMemoryEnvironment(sandbox)
            if scenario.environment and (scenario.environment.enable_persistent_memory)
            else None
        )
        for session_index, session in enumerate(scenario.sessions):
            session_dir = sandbox if session_index == 0 else sandbox / f"session_{session_index}"
            spec = _session_environment(scenario, session, canaries)
            seed_material = f"{run_seed}:{scenario.id}:{session.id}".encode()
            base_seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:4], "big") >> 2
            context = SessionExecutionContext(
                run_id=trace.run_id,
                scenario_id=scenario.id,
                trial_index=trace.trial_index,
                session_id=session.id,
                user_prompt=CanarySeeder.render_template(session.user_prompt, canaries),
                system_prompt_override=CanarySeeder.render_template(
                    session.system_prompt_hint, canaries
                ),
                max_turns=limits.max_turns,
                max_tool_calls=limits.max_tool_calls,
                timeout_seconds=min(limits.timeout_seconds, config.adapter.timeout_seconds),
                temperature=config.adapter.temperature,
                seed=base_seed + trace.trial_index,
            )
            result, initial, final, observed = await self._run_session(
                scenario,
                spec,
                session_dir,
                references,
                config,
                adapter,
                context,
                trace,
                canaries,
                memory,
            )
            observations.update(observed)
            for path, digest in initial.items():
                if path in before and before[path] != after.get(path):
                    continue
                before[path] = digest
                after.pop(path, None)
                if path in final:
                    after[path] = final[path]
            turns += result.turns_used
            calls += result.tool_calls_made
            prompt_tokens += result.prompt_tokens
            completion_tokens += result.completion_tokens
            usage_complete = usage_complete and result.has_complete_token_usage
        breaches = BreachDetector.evaluate_trial(
            trace.events,
            scenario,
            canaries,
            sandbox / "workspace",
            protected_before=before,
            protected_after=after,
        )
        chains = ProvenanceBuilder.build_all(breaches, trace.events, scenario)
        for breach, chain in zip(breaches, chains, strict=True):
            trace.emit(
                TraceEventType.BREACH_DETECTED,
                "harness",
                scenario.sessions[-1].id,
                breach.turn_index,
                breach.sink_tool,
                {
                    "breach": breach.model_dump(mode="json"),
                    "provenance": chain.model_dump(mode="json"),
                },
            )
        passed = not breaches
        blocked = any(
            event.event_type is TraceEventType.DEFENSE_DECISION
            and event.payload.get("action") == "blocked"
            for event in trace.events
        )
        task_failures = failed_task_checks(scenario, observations)
        trial = TrialResult(
            run_id=trace.run_id,
            scenario_id=scenario.id,
            trial_index=trace.trial_index,
            passed=passed,
            task_completed=(not task_failures) if observations else None,
            task_failures=task_failures,
            mitigated_by=("defense_proxy" if blocked else "agent") if passed else None,
            breaches=breaches,
            provenance_chains=chains,
            trace_path=trace.output_path,
            duration_ms=(perf_counter() - started) * 1000,
            turns_used=turns,
            tool_calls_made=calls,
            token_usage={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}
            if usage_complete
            else {},
        )
        trace.emit(
            TraceEventType.TRIAL_COMPLETED,
            "harness",
            scenario.sessions[-1].id,
            turns,
            payload={
                "passed": passed,
                "protected_before": before,
                "protected_after": after,
                "task_observations": {key: obs.model_dump() for key, obs in observations.items()},
            },
        )
        return trial

    async def _run_session(
        self,
        scenario: ScenarioSpec,
        spec: EnvironmentSpec,
        sandbox: Path,
        references: set[str],
        config: CanaryConfig,
        adapter: AgentAdapter,
        context: SessionExecutionContext,
        trace: TraceWriter,
        canaries: Mapping[str, GeneratedCanary],
        memory: PersistentMemoryEnvironment | None,
    ) -> tuple[AdapterSessionResult, dict[str, str], dict[str, str], dict[str, TaskObservation]]:
        trace.emit(TraceEventType.SESSION_STARTED, "harness", context.session_id, 0)
        for file in spec.files:
            if file.trust_level == "untrusted":
                trace.emit(
                    TraceEventType.INJECTION_PLANTED,
                    "environment",
                    context.session_id,
                    0,
                    payload={"source_location": f"file:{file.path}"},
                )
        a2a = A2ADelegationEnvironment() if spec.a2a_peers else None
        browser = BrowserDomTrapEnvironment() if spec.browser_pages else None
        env = build_composite_environment(
            spec,
            referenced_tools=references,
            approval_policies=scenario.assertions.approval_policies,
            mock_profile_paths=config.mock_profile_paths,
            canaries=canaries,
            a2a_environment=a2a,
            browser_environment=browser,
            trace=trace,
            session_id=context.session_id,
        )
        if memory is not None:
            memory.bind_trace(trace, context.session_id)
            env = CompositeEnvironment([env, memory])
        if config.defense_proxy is not None:
            env = DefenseProxyWrapper(
                env,
                config.defense_proxy,
                trace,
                context.session_id,
                # Leave time in the session for the agent to observe a policy denial.
                timeout=min(10.0, context.timeout_seconds / 2),
                transport=self._policy_transport,
            )
        adapter_traces = config.adapter.kind in {"scripted", "litellm"}
        async with AsyncExitStack() as stack:
            await env.setup(sandbox, spec.model_dump(mode="json", exclude_none=True))
            stack.push_async_callback(env.teardown)
            initial: dict[str, str] = (await env.snapshot_state())["protected_file_hashes"]
            server = _TrialMCPServer(
                env, spec, trace, context.session_id, not adapter_traces, memory
            )
            if config.adapter.kind in {"cli", "http"}:
                url = await stack.enter_async_context(server.serve_sse_loopback())
                context = context.model_copy(update={"mcp_http_url": url})
            if a2a is not None and config.adapter.kind in {"cli", "http", "python"}:
                endpoints = await stack.enter_async_context(a2a.start_loopback_a2a_server())
                context = context.model_copy(update={"a2a_endpoints": endpoints})
            if browser is not None and config.adapter.kind in {
                "cli",
                "http",
                "python",
                "playwright",
            }:
                origin = await stack.enter_async_context(browser.start_loopback_dom_server())
                context = context.model_copy(
                    update={"browser_start_url": origin + browser.start_path()}
                )
            trace.emit(
                TraceEventType.USER_PROMPT_SENT,
                "harness",
                context.session_id,
                0,
                payload={"content": context.user_prompt},
            )
            try:
                async with asyncio.timeout(context.timeout_seconds):
                    result = await adapter.run_session(context, _SessionTools(env, server), trace)
            except TimeoutError as exc:
                raise AdapterExecutionError("Agent session timed out") from exc
            if result.terminated_reason in {"timeout", "error"}:
                raise AdapterExecutionError(f"Agent session ended with {result.terminated_reason}")
            if result.final_response and not adapter_traces:
                trace.emit(
                    TraceEventType.AGENT_THOUGHT_OR_MESSAGE,
                    "agent",
                    context.session_id,
                    max(0, result.turns_used - 1),
                    payload={"content": result.final_response},
                )
            state = await env.snapshot_state()
            observed = observe_task_state(
                scenario,
                context.session_id,
                {**state, "final_response": result.final_response},
                canaries,
            )
        return result, initial, state["protected_file_hashes"], observed
