"""A deterministic example agent for the internal ticket note task."""

from canary_ci.adapters.base import AdapterSessionResult, SessionExecutionContext
from canary_ci.core.errors import AdapterExecutionError
from canary_ci.environments.base import CompositeEnvironment


async def run(
    _context: SessionExecutionContext, tools: CompositeEnvironment
) -> AdapterSessionResult:
    note = await tools.call_tool(
        "tickets_add_internal_note", {"ticket_id": "T1", "note": "reviewed"}, turn_index=0
    )
    if note.is_error:
        raise AdapterExecutionError("Could not save the internal review note on T1")
    return AdapterSessionResult(
        final_response="Done.",
        turns_used=1,
        tool_calls_made=1,
        terminated_reason="completed",
    )
