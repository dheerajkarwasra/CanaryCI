"""Read local browser fixtures using a network-restricted Chromium session."""

from importlib import import_module
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit

from ..core.errors import AdapterExecutionError, ConfigurationError, MissingExtraError
from ..core.models import AdapterConfig
from ..core.trace import TraceEventType, TraceWriter
from ..environments.base import CompositeEnvironment
from .base import AdapterSessionResult, AgentAdapter, SessionExecutionContext


def _loopback_origin(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and parsed.username is None
        ):
            return f"http://127.0.0.1:{parsed.port}"
    except ValueError:
        return None
    return None


async def intercept_browser_request(
    route: Any, origin: str, trace: TraceWriter, session_id: str
) -> None:
    request = route.request
    if _loopback_origin(request.url) == origin:
        await route.continue_()
        return
    await route.abort("blockedbyclient")
    trace.emit(
        TraceEventType.HTTP_EGRESS_CAPTURED,
        "environment",
        session_id,
        0,
        "browser_network",
        {
            "url": request.url,
            "method": request.method,
            "headers": request.headers,
            "body": request.post_data or "",
            "blocked": True,
        },
    )


class PlaywrightBrowserAdapter(AgentAdapter):
    def __init__(self, config: AdapterConfig) -> None:
        try:
            self._api: ModuleType = import_module("playwright.async_api")
        except ModuleNotFoundError as exc:
            if exc.name not in {"playwright", "playwright.async_api"}:
                raise
            raise MissingExtraError("Install with: uv pip install 'canary-ci[browser]'") from None

    async def run_session(
        self,
        ctx: SessionExecutionContext,
        env_dispatcher: CompositeEnvironment,
        trace: TraceWriter,
    ) -> AdapterSessionResult:
        start = ctx.browser_start_url
        origin = _loopback_origin(start) if start else None
        if start is None or origin is None:
            raise ConfigurationError("Playwright requires a loopback browser fixture URL")
        if not ctx.max_turns:
            return AdapterSessionResult(
                final_response="", turns_used=0, tool_calls_made=0, terminated_reason="max_turns"
            )

        async def route_request(route: Any) -> None:
            await intercept_browser_request(route, origin, trace, ctx.session_id)

        async def close_socket(route: Any) -> None:
            await route.close(code=1008, reason="Fixture browser policy")
            trace.emit(
                TraceEventType.HTTP_EGRESS_CAPTURED,
                "environment",
                ctx.session_id,
                0,
                "browser_network",
                {"url": route.url, "blocked": True},
            )

        try:
            async with self._api.async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-background-networking",
                        "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                        f"--proxy-server={origin}",
                        f"--proxy-bypass-list=<-loopback>;{origin.removeprefix('http://')}",
                    ],
                )
                try:
                    context = await browser.new_context(
                        service_workers="block", java_script_enabled=False
                    )
                    await context.route("**/*", route_request)
                    await context.route_web_socket("**/*", close_socket)
                    page = await context.new_page()
                    timeout_ms = ctx.timeout_seconds * 1000
                    await page.goto(start, wait_until="load", timeout=timeout_ms)
                    content: str = await page.locator("body").inner_text(timeout=timeout_ms)
                finally:
                    await browser.close()
        except self._api.Error as exc:
            raise AdapterExecutionError("Playwright could not inspect the browser fixture") from exc
        return AdapterSessionResult(
            final_response=content, turns_used=1, tool_calls_made=0, terminated_reason="completed"
        )
