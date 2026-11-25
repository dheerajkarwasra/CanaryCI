"""Seeded workspace tools and a pure Python shell simulator."""

import base64
import binascii
import hashlib
import re
import shlex
import shutil
from collections.abc import Iterator, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from ..core.errors import ConfigurationError
from ..core.models import FileSpec
from ..core.trace import TraceEventType
from .base import ToolCallResult, ToolSchema, TraceBoundEnvironment, TraceCallback
from .http_sink import HttpSinkEnvironment

_FILES: TypeAdapter[list[FileSpec]] = TypeAdapter(list[FileSpec])
_ENV: TypeAdapter[dict[str, str]] = TypeAdapter(dict[str, str])


def _tool(name: str, description: str, *fields: str, path_default: bool = False) -> ToolSchema:
    properties = {field: {"type": "string"} for field in fields}
    if path_default:
        properties["path"] = {"type": "string", "default": "."}
    return ToolSchema(
        name=name,
        description=description,
        input_schema={
            "type": "object",
            "properties": properties,
            "required": list(fields),
            "additionalProperties": False,
        },
    )


_TOOLS = (
    _tool("fs_list_directory", "List entries in a workspace directory", path_default=True),
    _tool("fs_read_file", "Read a workspace file", "path"),
    _tool("fs_write_file", "Write a workspace file", "path", "content"),
    _tool("fs_search_files", "Find workspace files matching a glob", "pattern", path_default=True),
    _tool("shell_exec", "Simulate a shell command in the workspace", "command"),
)
_TOOL_BY_NAME = {tool.name: tool for tool in _TOOLS}


class _BoundaryError(ConfigurationError):
    def __init__(self, path: str) -> None:
        super().__init__("Permission denied: outside workspace")
        self.path: str = path


class _ShellError(ConfigurationError):
    """An invalid or unsupported simulated shell operation."""


class WorkspaceFSEnvironment(TraceBoundEnvironment):
    def __init__(
        self, http_sink: HttpSinkEnvironment | None = None, on_event: TraceCallback | None = None
    ) -> None:
        super().__init__(on_event)
        self.http_sink: HttpSinkEnvironment | None = http_sink
        self.initial_protected_hashes: dict[str, str] = {}
        self._root: Path | None = None
        self._env: dict[str, str] = {}
        self._untrusted: dict[str, str] = {}

    @property
    def root(self) -> Path:
        if self._root is None:
            raise ConfigurationError("Workspace environment is not set up")
        return self._root

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        try:
            files = _FILES.validate_python(rendered_state.get("files", []))
            env = _ENV.validate_python(rendered_state.get("env_vars", {}))
        except ValidationError as exc:
            raise ConfigurationError("Invalid workspace files or env_vars") from exc
        root = sandbox_dir.resolve() / "workspace"
        if root.is_symlink():
            raise ConfigurationError("Workspace root must be a directory inside the sandbox")
        self._root = root
        self._env = env
        self.initial_protected_hashes = {}
        self._untrusted = {}
        try:
            root.mkdir(parents=True, exist_ok=True)
            targets = [(file, self._resolve(file.path, allow_root=False)) for file in files]
            if len({path for _, path in targets}) != len(targets):
                raise ConfigurationError("Duplicate seeded workspace path")
            for file, target in targets:
                data = file.content.encode("utf-8")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                relative = self._relative(target)
                if file.protected:
                    self.initial_protected_hashes[relative] = hashlib.sha256(data).hexdigest()
                if file.trust_level == "untrusted":
                    self._untrusted[relative] = f"file:{relative}"
        except (OSError, UnicodeError) as exc:
            await self.teardown()
            raise ConfigurationError("Could not seed workspace files") from exc
        except ConfigurationError:
            await self.teardown()
            raise

    def _resolve(self, value: str, *, allow_root: bool = True) -> Path:
        if value.startswith("~"):
            raise _BoundaryError(value)
        candidate = Path(
            value.removeprefix("/workspace").lstrip("/")
            if value == "/workspace" or value.startswith("/workspace/")
            else value
        )
        try:
            resolved = (self.root / candidate).resolve()
        except (RuntimeError, ValueError, OSError):
            raise _BoundaryError(value) from None
        if not resolved.is_relative_to(self.root):
            raise _BoundaryError(value)
        if not allow_root and resolved == self.root:
            raise _ShellError("Expected a file path inside the workspace")
        return resolved

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def _read(self, path: str) -> ToolCallResult:
        target = self._resolve(path, allow_root=False)
        source = self._untrusted.get(self._relative(target))
        return ToolCallResult(
            content=target.read_bytes().decode("utf-8"),
            contains_untrusted_content=source is not None,
            untrusted_source_id=source,
        )

    def _walk(self, path: str) -> Iterator[Path]:
        target = self._resolve(path)
        if not target.is_dir():
            if not target.is_file():
                raise _ShellError("Workspace path does not exist")
            yield target
            return
        for item in sorted(target.rglob("*")):
            if not item.is_symlink():
                yield item

    def list_tools(self) -> list[ToolSchema]:
        return list(_TOOLS)

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        tool = _TOOL_BY_NAME.get(name)
        if tool is None:
            return ToolCallResult(content=f"Unknown tool: {name}", is_error=True)
        properties = tool.input_schema["properties"]
        if (
            arguments.keys() - properties.keys()
            or any(field not in arguments for field in tool.input_schema["required"])
            or not all(isinstance(value, str) for value in arguments.values())
        ):
            return ToolCallResult(content=f"Invalid {name} arguments", is_error=True)
        path: str = arguments.get("path", ".")
        try:
            match name:
                case "fs_list_directory":
                    return ToolCallResult(
                        content="\n".join(
                            sorted(item.name for item in self._resolve(path).iterdir())
                        )
                    )
                case "fs_read_file":
                    return self._read(path)
                case "fs_write_file":
                    target = self._resolve(path, allow_root=False)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(arguments["content"].encode("utf-8"))
                    return ToolCallResult(content="OK")
                case "fs_search_files":
                    pattern = arguments["pattern"]
                    matches = [
                        self._relative(item)
                        for item in self._walk(path)
                        if item.is_file()
                        and (
                            fnmatchcase(item.name, pattern)
                            or fnmatchcase(self._relative(item), pattern)
                        )
                    ]
                    return ToolCallResult(content="\n".join(matches))
                case "shell_exec":
                    return GuardedShell(self).run(arguments["command"], turn_index)
        except _BoundaryError as exc:
            evidence = {"path_boundary_violation": exc.path}
            self._emit(TraceEventType.TOOL_RESPONSE, name, turn_index, evidence)
            return ToolCallResult(content=str(exc), structured_data=evidence, is_error=True)
        except _ShellError as exc:
            return ToolCallResult(content=str(exc), is_error=True)
        except (OSError, UnicodeError):
            return ToolCallResult(content="Workspace operation failed", is_error=True)
        raise ConfigurationError(f"Workspace tool is missing a handler: {name}")

    async def snapshot_state(self) -> dict[str, Any]:
        hashes: dict[str, str] = {}
        for relative in self.initial_protected_hashes:
            try:
                path = self._resolve(relative, allow_root=False)
                if path.is_file():
                    hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            except (_BoundaryError, FileNotFoundError):
                continue
            except OSError as exc:
                raise ConfigurationError(f"Could not hash protected file: {relative}") from exc
        return {"protected_file_hashes": hashes}

    async def teardown(self) -> None:
        self._root = None
        self._env = {}
        self._untrusted = {}
        self.initial_protected_hashes = {}


_SHELL_SYNTAX = re.compile(r"""\\.|'[^']*'|"(?:\\.|[^"\\])*"|\|\||&&|\$\(|[|;&<>`]""", re.DOTALL)
type _Pipeline = tuple[str, list[list[str]]]


def _split_stage(stage: str) -> list[str]:
    try:
        argv = shlex.split(stage)
    except ValueError:
        raise _ShellError("Invalid shell syntax") from None
    if not argv:
        raise _ShellError("Expected a simulated command")
    return argv


def _parse(command: str) -> list[_Pipeline]:
    pipelines: list[_Pipeline] = []
    stages: list[list[str]] = []
    start = 0
    gate = ";"
    for match in _SHELL_SYNTAX.finditer(command):
        separator = match[0]
        if separator in {"||", "&", ">", "<", "`", "$("}:
            raise _ShellError("Unsupported shell syntax")
        if separator not in {"|", "&&", ";"}:
            continue
        stages.append(_split_stage(command[start : match.start()]))
        start = match.end()
        if separator != "|":
            pipelines.append((gate, stages))
            gate, stages = separator, []
    tail = command[start:]
    if tail.strip() or stages or gate != ";" or not pipelines:
        stages.append(_split_stage(tail))
        pipelines.append((gate, stages))
    return pipelines


def _output(lines: Sequence[str]) -> str:
    return "".join(f"{line}\n" for line in lines)


def _with_source(result: ToolCallResult, source: str | None) -> ToolCallResult:
    if source is None or result.contains_untrusted_content:
        return result
    return result.model_copy(
        update={"contains_untrusted_content": True, "untrusted_source_id": source}
    )


class GuardedShell:
    def __init__(self, workspace: WorkspaceFSEnvironment) -> None:
        self._workspace: WorkspaceFSEnvironment = workspace

    def run(self, command: str, turn_index: int = 0) -> ToolCallResult:
        output: list[str] = []
        source: str | None = None
        result = ToolCallResult(content="")
        for gate, stages in _parse(command):
            if gate == "&&" and result.is_error:
                continue
            result = ToolCallResult(content="")
            for argv in stages:
                try:
                    completed = self._stage(argv, result.content, turn_index)
                except _ShellError as exc:
                    completed = ToolCallResult(content=str(exc), is_error=True)
                except (OSError, UnicodeError):
                    completed = ToolCallResult(content="Workspace operation failed", is_error=True)
                result = _with_source(completed, result.untrusted_source_id)
                if result.is_error:
                    break
            output.append(result.content)
            source = source or result.untrusted_source_id
        return _with_source(result.model_copy(update={"content": "".join(output)}), source)

    def _inputs(self, args: list[str], stdin: str) -> ToolCallResult:
        reads = [
            ToolCallResult(content=stdin) if path == "-" else self._workspace._read(path)
            for path in (args or ["-"])
        ]
        source = next(
            (read.untrusted_source_id for read in reads if read.contains_untrusted_content), None
        )
        return _with_source(ToolCallResult(content="".join(read.content for read in reads)), source)

    def _stage(self, argv: list[str], stdin: str, turn_index: int) -> ToolCallResult:
        name, *args = argv
        match name:
            case "pwd":
                return ToolCallResult(content="/workspace\n")
            case "ls":
                return ToolCallResult(content=self._ls(args))
            case "cat":
                return self._inputs(args, stdin)
            case "head" | "tail":
                count, paths = self._line_count(args)
                source = self._inputs(paths, stdin)
                lines = source.content.splitlines(keepends=True)
                selected = (lines[:count] if name == "head" else lines[-count:]) if count else []
                return source.model_copy(update={"content": "".join(selected)})
            case "grep":
                return self._grep(args, stdin)
            case "find":
                return ToolCallResult(content=self._find(args))
            case "env" | "printenv":
                return self._environment(name, args)
            case "echo":
                if args and args[0] == "-n":
                    return ToolCallResult(content=" ".join(args[1:]))
                return ToolCallResult(content=" ".join(args) + "\n")
            case "base64":
                return self._base64(args, stdin)
            case "rm" | "cp" | "mv":
                self._mutate(name, args)
                return ToolCallResult(content="")
            case "curl" | "wget":
                return self._http(args, stdin, turn_index)
        raise _ShellError(f"Unsupported simulated command: {name}")

    def _ls(self, args: list[str]) -> str:
        flags = {arg for arg in args if arg.startswith("-")}
        if not flags.issubset({"-a", "-l", "-al", "-la"}):
            raise _ShellError("Unsupported ls option")
        visible_dotfiles = any("a" in flag for flag in flags)
        items: list[str] = []
        for name in [arg for arg in args if arg not in flags] or ["."]:
            path = self._workspace._resolve(name)
            if path.is_dir():
                items.extend(
                    sorted(
                        item.name
                        for item in path.iterdir()
                        if visible_dotfiles or not item.name.startswith(".")
                    )
                )
            elif path.is_file():
                items.append(path.name)
            else:
                raise _ShellError("Workspace path does not exist")
        return _output(items)

    @staticmethod
    def _line_count(args: list[str]) -> tuple[int, list[str]]:
        if args[:1] == ["-n"] and len(args) > 1 and args[1].isascii() and args[1].isdigit():
            return min(int(args[1][:10]), 1_000_000_000), args[2:]
        if args and re.fullmatch(r"-[0-9]+", args[0]):
            return min(int(args[0][1:11]), 1_000_000_000), args[1:]
        if args and args[0].startswith("-") and args[0] != "-":
            raise _ShellError("Expected a nonnegative line count")
        return 10, args

    def _grep(self, args: list[str], stdin: str) -> ToolCallResult:
        flags: set[str] = set()
        while args and args[0] in {"-i", "-v", "-n"}:
            flags.add(args.pop(0))
        if not args:
            raise _ShellError("Expected a grep pattern")
        try:
            pattern = re.compile(args[0], re.IGNORECASE if "-i" in flags else 0)
        except re.error:
            raise _ShellError("Invalid grep pattern") from None
        source = self._inputs(args[1:], stdin)
        lines = [
            f"{index}:{line}" if "-n" in flags else line
            for index, line in enumerate(source.content.splitlines(keepends=True), 1)
            if bool(pattern.search(line)) != ("-v" in flags)
        ]
        return source.model_copy(update={"content": "".join(lines), "is_error": not lines})

    def _find(self, args: list[str]) -> str:
        path = args.pop(0) if args and not args[0].startswith("-") else "."
        pattern, kind = "*", None
        if len(args) % 2:
            raise _ShellError("Expected find option and value")
        for option, value in zip(args[::2], args[1::2], strict=True):
            if option == "-name":
                pattern = value
            elif option == "-type" and value in {"f", "d"}:
                kind = value
            else:
                raise _ShellError("Unsupported find option")
        return _output(
            [
                self._workspace._relative(item)
                for item in self._workspace._walk(path)
                if fnmatchcase(item.name, pattern)
                and (kind is None or (item.is_file() if kind == "f" else item.is_dir()))
            ]
        )

    def _environment(self, name: str, args: list[str]) -> ToolCallResult:
        variables = self._workspace._env
        if name == "env" and args:
            raise _ShellError("The simulated env command accepts no arguments")
        if name == "printenv" and args:
            return ToolCallResult(
                content=_output([variables[key] for key in args if key in variables]),
                is_error=any(key not in variables for key in args),
            )
        return ToolCallResult(
            content=_output([f"{key}={value}" for key, value in sorted(variables.items())])
        )

    def _base64(self, args: list[str], stdin: str) -> ToolCallResult:
        decode = bool(args and args[0] in {"-d", "-D", "--decode"})
        paths = args[1:] if decode else args
        source = self._inputs(paths, stdin)
        if decode:
            try:
                result = base64.b64decode("".join(source.content.split()), validate=True).decode(
                    "utf-8", errors="replace"
                )
            except (binascii.Error, ValueError):
                raise _ShellError("Invalid Base64 input") from None
        else:
            result = base64.b64encode(source.content.encode("utf-8")).decode("ascii")
        return source.model_copy(update={"content": result})

    def _mutate(self, name: str, args: list[str]) -> None:
        workspace = self._workspace
        if name == "rm":
            flags = {arg for arg in args if arg.startswith("-")}
            if not flags.issubset({"-f", "-r", "-rf", "-fr"}):
                raise _ShellError("Unsupported rm option")
            targets = [
                workspace._resolve(arg, allow_root=False) for arg in args if arg not in flags
            ]
            if not targets:
                raise _ShellError("Expected a workspace path")
            force = any("f" in flag for flag in flags)
            recursive = any("r" in flag for flag in flags)
            for target in targets:
                if recursive and target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=force)
            return
        if len(args) != 2 or any(arg.startswith("-") for arg in args):
            raise _ShellError(f"Expected a source and destination for {name}")
        source, target = (workspace._resolve(arg, allow_root=False) for arg in args)
        if target.is_dir():
            target = workspace._resolve(str(target / source.name), allow_root=False)
        if not source.is_file():
            raise _ShellError(f"Expected a workspace file for {name}")
        if name == "cp":
            shutil.copyfile(source, target)
        else:
            source.rename(target)
        original = workspace._relative(source)
        if marker := workspace._untrusted.get(original):
            workspace._untrusted[workspace._relative(target)] = marker

    def _http(self, args: list[str], stdin: str, turn_index: int) -> ToolCallResult:
        sink = self._workspace.http_sink
        if sink is None:
            raise _ShellError("No synthetic HTTP sink is configured")
        url: str | None = None
        method: str | None = None
        headers: dict[str, str] = {}
        data: list[str] = []
        options = iter(args)
        for arg in options:
            if arg in {"-s", "-S", "-sS", "-q"}:
                continue
            if arg in {"-X", "--request", "--method"}:
                method = next(options, None)
                if not method:
                    raise _ShellError("Expected an HTTP method")
            elif arg in {"-H", "--header"}:
                key, colon, value = (next(options, "")).partition(":")
                if not colon or not key.strip():
                    raise _ShellError("Expected an HTTP header")
                headers[key.strip()] = value.strip()
            elif arg in {
                "-d",
                "--data",
                "--data-binary",
                "--data-raw",
                "--post-data",
                "--post-file",
            }:
                payload = next(options, None)
                if payload is None:
                    raise _ShellError("Expected an HTTP request body")
                if arg == "--post-file":
                    payload = self._inputs([payload], stdin).content
                elif payload.startswith("@") and arg in {"-d", "--data", "--data-binary"}:
                    payload = self._inputs([payload[1:]], stdin).content
                data.append(payload)
            elif arg == "-O":
                if next(options, None) != "-":
                    raise _ShellError("Expected standard output for the simulated request")
            elif url is None and not arg.startswith("-"):
                url = arg
            else:
                raise _ShellError("Unsupported HTTP command option")
        if url is None:
            raise _ShellError("Expected an HTTP URL")
        return sink.http_fetch(
            url,
            method or ("POST" if data else "GET"),
            headers,
            "&".join(data),
            turn_index=turn_index,
        )
