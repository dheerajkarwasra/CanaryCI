"""In-memory HTTP capture, a loopback listener, and simulated human approval."""

import asyncio
import socket
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import uvicorn
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..core.errors import ConfigurationError
from ..core.trace import TraceEventType
from .base import ToolCallResult, ToolSchema, TraceBoundEnvironment, TraceCallback


class _FetchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""


class CapturedRequest(_FetchArgs):
    turn_index: int


class _MockUrl(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str | None = None
    url_prefix: str | None = None
    match: Literal["exact", "prefix"] = "exact"
    status: int = Field(default=200, strict=True, ge=200, le=599)
    body: str = "ok"
    trust_level: Literal["trusted", "untrusted"] = "trusted"

    @model_validator(mode="after")
    def _check_pattern(self) -> "_MockUrl":
        if not (bool(self.url) ^ bool(self.url_prefix)):
            raise ValueError("Set exactly one of url or url_prefix")
        if not self.pattern.startswith("/") and not _is_http_url(self.pattern):
            raise ValueError("Expected an HTTP URL or loopback path")
        return self

    @property
    def pattern(self) -> str:
        return self.url_prefix or self.url or ""

    @property
    def prefix(self) -> bool:
        return self.url_prefix is not None or self.match == "prefix"


_MOCK_URLS: TypeAdapter[list[_MockUrl]] = TypeAdapter(list[_MockUrl])
_LOOPBACK = "127.0.0.1"


def _is_http_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return parts.scheme in {"http", "https"} and bool(parts.hostname)
    except ValueError:
        return False


def _path_query(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    return f"{path}?{parts.query}" if parts.query else path


def _same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


class _LoopbackServer(uvicorn.Server):
    @contextmanager
    def capture_signals(self) -> Iterator[None]:
        # The listener is embedded in the trial, which owns process signals.
        yield


class HttpSinkEnvironment(TraceBoundEnvironment):
    def __init__(self, on_event: TraceCallback | None = None) -> None:
        super().__init__(on_event)
        self.captured_requests: list[CapturedRequest] = []
        self._mocks: list[_MockUrl] = []

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        try:
            mocks = _MOCK_URLS.validate_python(rendered_state.get("mock_urls", []))
        except ValidationError as exc:
            raise ConfigurationError("Invalid mock_urls fixtures") from exc
        self._mocks = sorted(mocks, key=lambda mock: (mock.prefix, -len(mock.pattern)))
        self.captured_requests.clear()

    def list_tools(self) -> list[ToolSchema]:
        return [
            ToolSchema(
                name="http_fetch",
                description="Fetch a URL through the synthetic HTTP sink",
                input_schema=_FetchArgs.model_json_schema(),
                is_sink=True,
                trust_zone="external_untrusted",
            )
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        if name != "http_fetch":
            return ToolCallResult(content=f"Unknown tool: {name}", is_error=True)
        try:
            args = _FetchArgs.model_validate(arguments)
        except ValidationError:
            return ToolCallResult(content="Invalid http_fetch arguments", is_error=True)
        return self.http_fetch(
            args.url, args.method, args.headers, args.body, turn_index=turn_index
        )

    def http_fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str = "",
        *,
        turn_index: int = 0,
    ) -> ToolCallResult:
        if not _is_http_url(url):
            return ToolCallResult(content="Expected an HTTP or HTTPS URL", is_error=True)
        return self._capture(
            CapturedRequest(
                url=url,
                method=method.upper(),
                headers=headers or {},
                body=body,
                turn_index=turn_index,
            )
        )

    def _match(self, url: str, loopback: bool) -> _MockUrl | None:
        for mock in self._mocks:
            pattern = mock.pattern
            if pattern.startswith("/"):
                if not loopback:
                    continue
                actual = _path_query(url)
            elif loopback:
                actual, pattern = _path_query(url), _path_query(pattern)
            else:
                actual = url
                if mock.prefix and not _same_origin(actual, pattern):
                    continue
            if actual.startswith(pattern) if mock.prefix else actual == pattern:
                return mock
        return None

    def _capture(self, request: CapturedRequest, *, loopback: bool = False) -> ToolCallResult:
        self.captured_requests.append(request)
        self._emit(
            TraceEventType.HTTP_EGRESS_CAPTURED,
            "http_fetch",
            request.turn_index,
            request.model_dump(),
        )
        mock = self._match(request.url, loopback)
        body, status = (mock.body, mock.status) if mock else ("ok", 200)
        untrusted = mock is not None and mock.trust_level == "untrusted"
        return ToolCallResult(
            content=body,
            structured_data={"status": status, "body": body},
            contains_untrusted_content=untrusted,
            untrusted_source_id=f"url:{request.url}" if untrusted else None,
        )

    async def _respond(self, request: Request) -> Response:
        capture = CapturedRequest(
            url=str(request.url),
            method=request.method,
            headers=dict(request.headers),
            body=(await request.body()).decode("utf-8", errors="replace"),
            turn_index=-1,
        )
        result = self._capture(capture, loopback=True)
        assert result.structured_data is not None
        status = int(result.structured_data["status"])
        content = "" if status in {204, 304} else result.content
        return Response(content, status_code=status, media_type="text/plain")

    @asynccontextmanager
    async def start_loopback_listener(self) -> AsyncIterator[str]:
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
        app = Starlette(routes=[Route("/{path:path}", self._respond, methods=methods)])
        server = _LoopbackServer(
            uvicorn.Config(
                app,
                host=_LOOPBACK,
                port=0,
                loop="asyncio",
                lifespan="off",
                ws="none",
                proxy_headers=False,
                access_log=False,
                log_config=None,
                timeout_graceful_shutdown=1,
            )
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind((_LOOPBACK, 0))
            except OSError as exc:
                raise ConfigurationError("Could not bind the loopback HTTP listener") from exc
            port = listener.getsockname()[1]
            task = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                try:
                    async with asyncio.timeout(5):
                        while not server.started:
                            if task.done():
                                await task
                                raise ConfigurationError(
                                    "Loopback HTTP listener exited during startup"
                                )
                            await asyncio.sleep(0.01)
                except TimeoutError:
                    raise ConfigurationError("Loopback HTTP listener startup timed out") from None
                yield f"http://{_LOOPBACK}:{port}"
            finally:
                server.should_exit = True
                try:
                    await asyncio.wait_for(task, timeout=5)
                except TimeoutError:
                    raise ConfigurationError("Loopback HTTP listener shutdown timed out") from None

    async def snapshot_state(self) -> dict[str, Any]:
        return {"captured_requests": [request.model_dump() for request in self.captured_requests]}

    async def teardown(self) -> None:
        self._mocks.clear()


class _ApprovalArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_tool: str
    proposed_args: dict[str, Any]
    human_summary: str


class HumanApprovalEnvironment(TraceBoundEnvironment):
    def __init__(self, on_event: TraceCallback | None = None) -> None:
        super().__init__(on_event)
        self._approved: bool = True

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        decision = rendered_state.get("approval_response", "APPROVED")
        if decision not in ("APPROVED", "DENIED"):
            raise ConfigurationError("approval_response must be APPROVED or DENIED")
        self._approved = decision == "APPROVED"

    def list_tools(self) -> list[ToolSchema]:
        return [
            ToolSchema(
                name="request_human_approval",
                description="Request a simulated approval",
                input_schema=_ApprovalArgs.model_json_schema(),
            )
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        if name != "request_human_approval":
            return ToolCallResult(content=f"Unknown tool: {name}", is_error=True)
        try:
            args = _ApprovalArgs.model_validate(arguments)
        except ValidationError:
            return ToolCallResult(content="Invalid request_human_approval arguments", is_error=True)
        return self.request_human_approval(
            args.target_tool, args.proposed_args, args.human_summary, turn_index=turn_index
        )

    def request_human_approval(
        self,
        target_tool: str,
        proposed_args: dict[str, Any],
        human_summary: str,
        *,
        turn_index: int = 0,
    ) -> ToolCallResult:
        result = {"approved": self._approved}
        self._emit(
            TraceEventType.APPROVAL_REQUESTED,
            "request_human_approval",
            turn_index,
            {
                "target_tool": target_tool,
                "proposed_args": proposed_args,
                "human_summary": human_summary,
                **result,
            },
        )
        return ToolCallResult(
            content="APPROVED" if self._approved else "DENIED", structured_data=result
        )

    async def snapshot_state(self) -> dict[str, Any]:
        return {}

    async def teardown(self) -> None:
        self._approved = True
