"""Run a configured agent executable with a scrubbed environment."""

import asyncio
import json
import os
import signal
from collections.abc import Sequence
from contextlib import suppress

from ..core.errors import AdapterExecutionError, ConfigurationError
from ..core.trace import TraceWriter
from ..environments.base import CompositeEnvironment
from .base import (
    AdapterSessionResult,
    AgentAdapter,
    SessionExecutionContext,
    sanitize_subprocess_env,
)


class CliSubprocessAdapter(AgentAdapter):
    def __init__(self, command: Sequence[str], pass_env: Sequence[str] = ()) -> None:
        if isinstance(command, str) or not command or not command[0]:
            raise ConfigurationError("The CLI adapter requires a nonempty command argv")
        self._command: tuple[str, ...] = tuple(command)
        self._pass_env: tuple[str, ...] = tuple(pass_env)

    async def run_session(
        self, ctx: SessionExecutionContext, env_dispatcher: CompositeEnvironment, trace: TraceWriter
    ) -> AdapterSessionResult:
        env = sanitize_subprocess_env(os.environ, self._pass_env)
        env.update(
            CANARY_PROMPT=ctx.user_prompt,
            CANARY_SESSION_ID=ctx.session_id,
            CANARY_MCP_SSE_URL=ctx.mcp_http_url or "",
            CANARY_A2A_ENDPOINTS_JSON=json.dumps(ctx.a2a_endpoints, sort_keys=True),
            CANARY_BROWSER_START_URL=ctx.browser_start_url or "",
        )
        try:
            process = await asyncio.create_subprocess_exec(  # noqa: S603 - Trusted project argv.
                *self._command,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name == "posix",
            )
        except (OSError, ValueError) as exc:
            raise AdapterExecutionError("Could not start the CLI agent") from exc

        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=ctx.timeout_seconds)
        except TimeoutError:
            await _stop(process)
            return AdapterSessionResult(
                final_response="", turns_used=0, tool_calls_made=0, terminated_reason="timeout"
            )
        except asyncio.CancelledError:
            await _stop(process)
            raise

        if process.returncode != 0:
            raise AdapterExecutionError(f"CLI agent exited with status {process.returncode}")
        return AdapterSessionResult(
            final_response=stdout.decode("utf-8", errors="replace"),
            turns_used=int(bool(stdout)),
            tool_calls_made=0,
            terminated_reason="completed",
        )


async def _stop(process: asyncio.subprocess.Process) -> None:
    with suppress(ProcessLookupError):
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.returncode is None:
            process.kill()
    await process.communicate()
