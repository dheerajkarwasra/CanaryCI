"""Serve fixture agent cards and deterministic local A2A task responses."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..core.errors import ConfigurationError
from ..core.models import TrustZone
from ..core.trace import TraceEventType
from .base import ToolCallResult, ToolSchema, TraceBoundEnvironment
from .mcp_server import _serve


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class A2APeerSpec(BaseModel):
    peer_name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    display_name: str
    claimed_role: str
    trust_zone: TrustZone
    trust_level: Literal["trusted", "untrusted"]
    agent_card_description: str
    response_text: str
    redirect_to_peer: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class _Discover(_Model):
    peer_name: str


class _Delegate(_Discover):
    task_instruction: str
    context_data: str = ""
    auth_token: str = ""


class _RpcRequest(_Model):
    jsonrpc: Literal["2.0"]
    id: str | int | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class _Task(_Model):
    id: str
    status: Literal["completed"] = "completed"
    content: str


class _AgentCard(_Model):
    name: str
    description: str
    url: str
    claimed_role: str
    capabilities: dict[str, bool] = Field(default_factory=lambda: {"streaming": False})
    authentication: dict[str, list[str]] = Field(default_factory=lambda: {"schemes": list[str]()})
    skills: list[dict[str, str]] = Field(
        default_factory=lambda: [
            {
                "id": "fixture-delegation",
                "name": "Fixture delegation",
                "description": "Return a recorded response for a synthetic task",
            },
        ]
    )


_PEERS = TypeAdapter(list[A2APeerSpec])
_TOOLS: tuple[ToolSchema, ...] = (
    ToolSchema(
        name="a2a_discover_peer",
        description="Read a fixture agent card",
        input_schema=_Discover.model_json_schema(),
    ),
    ToolSchema(
        name="a2a_delegate_task",
        description="Delegate to a configured fixture peer",
        input_schema=_Delegate.model_json_schema(),
    ),
)


class A2ADelegationEnvironment(TraceBoundEnvironment):
    def __init__(self) -> None:
        super().__init__()
        self._peers: dict[str, A2APeerSpec] = {}
        self._tasks: dict[tuple[str, str], _Task] = {}
        self._addresses: dict[str, str] = {}
        self._wire_turn: int = 0

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        try:
            peers = _PEERS.validate_python(rendered_state.get("a2a_peers", []))
        except ValidationError:
            raise ConfigurationError("Invalid A2A fixture peers") from None
        self._peers = {peer.peer_name: peer for peer in peers}
        if len(peers) != len(self._peers):
            raise ConfigurationError("Duplicate A2A fixture peer")
        if any(
            peer.redirect_to_peer and peer.redirect_to_peer not in self._peers for peer in peers
        ):
            raise ConfigurationError("Unknown A2A fixture referral peer")
        self._tasks.clear()
        self._wire_turn = 0

    def list_tools(self) -> list[ToolSchema]:
        return list(_TOOLS)

    def classify_tool_call(self, schema: ToolSchema, arguments: dict[str, Any]) -> ToolSchema:
        name = arguments.get("peer_name")
        peer = self._peers.get(name) if isinstance(name, str) else None
        if schema.name != "a2a_delegate_task" or peer is None:
            return schema
        return schema.model_copy(
            update={
                "trust_zone": peer.trust_zone.value,
                "is_sink": peer.trust_zone is TrustZone.EXTERNAL_UNTRUSTED,
            }
        )

    def _card(self, peer: A2APeerSpec) -> _AgentCard:
        return _AgentCard(
            name=peer.display_name,
            description=peer.agent_card_description,
            url=self._addresses.get(peer.peer_name, f"/peers/{peer.peer_name}/a2a"),
            claimed_role=peer.claimed_role,
        )

    @staticmethod
    def _response(peer: A2APeerSpec, content: str) -> ToolCallResult:
        untrusted = peer.trust_level == "untrusted"
        return ToolCallResult(
            content=content,
            contains_untrusted_content=untrusted,
            untrusted_source_id=f"a2a_peer:{peer.peer_name}" if untrusted else None,
        )

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        try:
            if name == "a2a_discover_peer":
                discover = _Discover.model_validate(arguments)
                peer = self._peers.get(discover.peer_name)
                if peer is not None:
                    return self._response(peer, self._card(peer).model_dump_json())
                return ToolCallResult(content="Unknown fixture peer", is_error=True)
            if name != "a2a_delegate_task":
                return ToolCallResult(content=f"Unknown A2A tool: {name}", is_error=True)
            request = _Delegate.model_validate(arguments)
        except ValidationError:
            return ToolCallResult(content=f"Invalid arguments for {name}", is_error=True)
        peer = self._peers.get(request.peer_name)
        if peer is None:
            return ToolCallResult(content="Unknown fixture peer", is_error=True)
        self._emit(
            TraceEventType.A2A_MESSAGE,
            name,
            turn_index,
            {
                "arguments": request.model_dump(mode="json"),
                "trust_zone": peer.trust_zone.value,
                "is_sink": peer.trust_zone is TrustZone.EXTERNAL_UNTRUSTED,
                "sink_key": f"a2a_peer:{peer.peer_name}",
            },
        )
        referral = f"\nFixture referral: {peer.redirect_to_peer}." if peer.redirect_to_peer else ""
        return self._response(peer, peer.response_text + referral)

    async def _get_card(self, request: Request) -> JSONResponse:
        peer = self._peers.get(request.path_params["peer_name"])
        if peer is None:
            return JSONResponse({"error": "Unknown fixture peer"}, status_code=404)
        response = self._response(peer, self._card(peer).model_dump_json())
        self._emit(
            TraceEventType.TOOL_RESPONSE,
            "a2a_discover_peer",
            self._wire_turn,
            response.model_dump(mode="json"),
        )
        return JSONResponse(self._card(peer).model_dump(mode="json"))

    async def _rpc(self, request: Request) -> JSONResponse:
        try:
            call = _RpcRequest.model_validate_json(await request.body())
        except ValidationError:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": "Invalid request",
                    },
                }
            )
        base = {"jsonrpc": "2.0", "id": call.id}
        peer_name = request.path_params["peer_name"]
        if call.method == "tasks/get":
            task_id = call.params.get("id")
            task = self._tasks.get((peer_name, task_id)) if isinstance(task_id, str) else None
            if task is None:
                return JSONResponse({**base, "error": {"code": -32001, "message": "Unknown task"}})
            return JSONResponse({**base, "result": task.model_dump(mode="json")})
        if call.method != "tasks/send":
            return JSONResponse({**base, "error": {"code": -32601, "message": "Unknown method"}})
        params = dict(call.params)
        task_id = params.pop("id", f"task-{len(self._tasks) + 1}")
        if not isinstance(task_id, str) or not task_id or (peer_name, task_id) in self._tasks:
            return JSONResponse({**base, "error": {"code": -32602, "message": "Invalid task ID"}})
        turn = self._wire_turn
        self._wire_turn += 1
        result = await self.call_tool("a2a_delegate_task", {**params, "peer_name": peer_name}, turn)
        if result.is_error:
            return JSONResponse({**base, "error": {"code": -32602, "message": result.content}})
        self._emit(
            TraceEventType.TOOL_RESPONSE, "a2a_delegate_task", turn, result.model_dump(mode="json")
        )
        task = _Task(id=task_id, content=result.content)
        self._tasks[peer_name, task_id] = task
        return JSONResponse({**base, "result": task.model_dump(mode="json")})

    @asynccontextmanager
    async def start_loopback_a2a_server(self) -> AsyncIterator[dict[str, str]]:
        app = Starlette(
            routes=[
                Route("/peers/{peer_name}/.well-known/agent.json", self._get_card),
                Route("/peers/{peer_name}/a2a", self._rpc, methods=["POST"]),
            ]
        )
        async with _serve(app) as origin:
            self._addresses = {name: f"{origin}/peers/{name}/a2a" for name in self._peers}
            try:
                yield dict(self._addresses)
            finally:
                self._addresses.clear()

    async def snapshot_state(self) -> dict[str, Any]:
        return {"a2a_tasks": [task.model_dump(mode="json") for task in self._tasks.values()]}

    async def teardown(self) -> None:
        self._peers.clear()
        self._tasks.clear()
