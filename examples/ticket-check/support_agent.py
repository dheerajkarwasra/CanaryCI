"""A deterministic example agent for the internal ticket note task."""

from canary_ci.adapters.base import AdapterSessionResult, SessionExecutionContext
from canary_ci.environments.base import CompositeEnvironment


async def run(
    _context: SessionExecutionContext, tools: CompositeEnvironment
) -> AdapterSessionResult:
    return AdapterSessionResult(
        final_response="Done.",
        turns_used=1,
        tool_calls_made=0,
        terminated_reason="completed",
    )
