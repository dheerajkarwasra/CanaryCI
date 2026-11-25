"""Invoke a configured Python agent in-process."""

from collections.abc import Callable
from importlib import import_module
from inspect import isawaitable

from pydantic import ValidationError

from ..core.errors import AdapterExecutionError, CanaryCIError, ConfigurationError
from ..core.trace import TraceWriter
from ..environments.base import CompositeEnvironment
from .base import AdapterSessionResult, AgentAdapter, SessionExecutionContext


class PythonCallableAdapter(AgentAdapter):
    def __init__(self, callable_path: str) -> None:
        module_path, separator, function_name = callable_path.partition(":")
        if not separator or not module_path or not function_name.isidentifier():
            raise ConfigurationError("The Python adapter requires module_path:func_name")
        try:
            module = import_module(module_path)
        except ImportError as exc:
            raise ConfigurationError(
                f"Could not import Python agent module: {module_path}"
            ) from exc
        except Exception as exc:
            raise AdapterExecutionError(
                f"Python agent module failed to initialize: {module_path}"
            ) from exc
        function = getattr(module, function_name, None)
        if not callable(function):
            raise ConfigurationError(f"Python agent callable not found: {callable_path}")
        self._function: Callable[[SessionExecutionContext, CompositeEnvironment], object] = function

    async def run_session(
        self, ctx: SessionExecutionContext, env_dispatcher: CompositeEnvironment, trace: TraceWriter
    ) -> AdapterSessionResult:
        try:
            result = self._function(ctx, env_dispatcher)
            if isawaitable(result):
                result = await result
        except CanaryCIError:
            raise
        except Exception as exc:
            raise AdapterExecutionError("The Python agent failed") from exc
        try:
            return AdapterSessionResult.model_validate(result)
        except ValidationError:
            raise AdapterExecutionError(
                "The Python agent returned an invalid session result"
            ) from None
