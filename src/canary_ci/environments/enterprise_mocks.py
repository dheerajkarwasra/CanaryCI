"""Deterministic enterprise tools backed by trial-local fixtures."""

import hashlib
import json
import re
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from email.utils import getaddresses
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    create_model,
)

from ..canary.seeder import GeneratedCanary
from ..core.errors import ConfigurationError
from ..core.models import ApprovalPolicySpec, DatabaseSpec, EnvironmentSpec
from ..core.trace import TraceWriter
from .a2a_mock import A2ADelegationEnvironment
from .base import CompositeEnvironment, HoneyEnvironment, ToolCallResult, ToolSchema
from .browser_dom_server import BrowserDomTrapEnvironment
from .custom_profile import CustomMockProfileEnvironment, load_custom_profiles
from .http_sink import HttpSinkEnvironment, HumanApprovalEnvironment
from .workspace_fs import WorkspaceFSEnvironment

type _Zone = Literal["internal_trusted", "internal_restricted", "external_untrusted"]
_STRING_LIST = TypeAdapter(list[str])


@dataclass(frozen=True, slots=True)
class _Tool:
    schema: ToolSchema
    arguments: type[BaseModel]


def _tool(
    name: str,
    description: str,
    *,
    sink: bool = False,
    zone: _Zone = "internal_trusted",
    **fields: tuple[Any, Any],
) -> _Tool:
    definitions: dict[str, Any] = dict(fields)
    model = create_model(
        f"{name}Arguments",
        __config__=ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False),
        **definitions,
    )
    return _Tool(
        ToolSchema(
            name=name,
            description=description,
            input_schema=model.model_json_schema(),
            is_sink=sink,
            trust_zone=zone,
        ),
        model,
    )


def _result(data: dict[str, Any], source: str | None = None) -> ToolCallResult:
    return ToolCallResult(
        content=json.dumps(data, sort_keys=True, ensure_ascii=False),
        structured_data=data,
        contains_untrusted_content=source is not None,
        untrusted_source_id=source,
    )


def _error(message: str) -> ToolCallResult:
    return ToolCallResult(content=message, is_error=True)


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    trust_level: Literal["trusted", "untrusted"] = "trusted"


def _records[Record: _Record, Key: (str, int)](
    model: type[Record], values: Any, key: Callable[[Record], Key], label: str
) -> dict[Key, Record]:
    if not isinstance(values, list):
        raise ConfigurationError(f"Expected a list for {label}")
    result: dict[Key, Record] = {}
    for index, value in enumerate(values):
        try:
            record = model.model_validate(value)
        except ValidationError as exc:
            raise ConfigurationError(f"Invalid {label} fixture at index {index}") from exc
        identifier = key(record)
        if identifier in result:
            raise ConfigurationError(f"Duplicate {label} identifier: {identifier}")
        result[identifier] = record
    return result


def _dump(records: Iterable[_Record]) -> list[dict[str, Any]]:
    return [record.model_dump(mode="json") for record in records]


def _read(record: _Record, source: str) -> ToolCallResult:
    return _result(
        record.model_dump(mode="json"), source if record.trust_level == "untrusted" else None
    )


def _list_records[Record: _Record](
    field: str, records: Sequence[Record], source: Callable[[Record], str]
) -> ToolCallResult:
    untrusted = next(
        (source(record) for record in records if record.trust_level == "untrusted"), None
    )
    return _result({field: _dump(records)}, untrusted)


class _Provider(ABC):
    _tools: tuple[_Tool, ...]

    def list_tools(self) -> list[ToolSchema]:
        return [tool.schema for tool in self._tools]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], turn_index: int
    ) -> ToolCallResult:
        tool = next((tool for tool in self._tools if tool.schema.name == name), None)
        if tool is None:
            return _error(f"Unknown tool: {name}")
        try:
            values = tool.arguments.model_validate(arguments).model_dump()
        except ValidationError:
            return _error(f"Invalid {name} arguments")
        return self._invoke(name, values)

    @abstractmethod
    def _invoke(self, name: str, args: dict[str, Any]) -> ToolCallResult: ...


class _PullRequest(_Record):
    id: int = Field(validation_alias=AliasChoices("id", "pr_number"))
    title: str = ""
    author: str = ""
    base: str = ""
    head: str = ""
    body: str = ""
    diff: str = ""
    comments: list[str | dict[str, Any]] = Field(default_factory=list)
    state: str = "open"


class _Issue(_Record):
    id: int
    title: str = ""
    author: str = ""
    body: str = ""
    labels: list[str] = Field(default_factory=list)
    state: str = "open"


class GitPRHoneyEnvironment(_Provider):
    _tools: tuple[_Tool, ...] = (
        _tool("git_list_pull_requests", "List fixture pull requests by state", state=(str, "open")),
        _tool("git_get_pull_request", "Read a fixture pull request", pr_number=(int, ...)),
        _tool(
            "git_post_pr_comment",
            "Post a simulated pull request comment",
            sink=True,
            zone="external_untrusted",
            pr_number=(int, ...),
            body=(str, ...),
        ),
        _tool(
            "git_merge_pull_request",
            "Merge a fixture pull request",
            sink=True,
            pr_number=(int, ...),
        ),
        _tool("git_list_issues", "List fixture issues"),
        _tool("git_get_issue", "Read a fixture issue", issue_number=(int, ...)),
    )

    def __init__(self) -> None:
        self._prs: dict[int, _PullRequest] = {}
        self._issues: dict[int, _Issue] = {}
        self._repo_files: dict[str, str] = {}

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        self._prs = _records(
            _PullRequest, rendered_state.get("pull_requests", []), lambda pr: pr.id, "pull requests"
        )
        self._issues = _records(
            _Issue, rendered_state.get("issues", []), lambda issue: issue.id, "issues"
        )
        try:
            self._repo_files = TypeAdapter(dict[str, str]).validate_python(
                rendered_state.get("repo_files", {})
            )
        except ValidationError as exc:
            raise ConfigurationError("Invalid repo_files fixtures") from exc

    def _invoke(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        if name == "git_list_pull_requests":
            records = [pr for pr in self._prs.values() if args["state"] in ("all", pr.state)]
            return _list_records("pull_requests", records, lambda pr: f"pr:{pr.id}")
        if name == "git_list_issues":
            return _list_records(
                "issues", list(self._issues.values()), lambda issue: f"issue:{issue.id}"
            )
        if name == "git_get_issue":
            issue = self._issues.get(args["issue_number"])
            return _read(issue, f"issue:{issue.id}") if issue else _error("Issue not found")
        pr = self._prs.get(args["pr_number"])
        if pr is None:
            return _error("Pull request not found")
        match name:
            case "git_get_pull_request":
                return _read(pr, f"pr:{pr.id}")
            case "git_post_pr_comment":
                self._prs[pr.id] = pr.model_copy(update={"comments": [*pr.comments, args["body"]]})
                return _result({"pr_number": pr.id, "posted": True})
            case "git_merge_pull_request":
                if pr.state not in {"open", "merged"}:
                    return _error("Pull request is closed")
                self._prs[pr.id] = pr.model_copy(update={"state": "merged"})
                return _result({"pr_number": pr.id, "state": "merged"})
        raise ConfigurationError(f"Missing Git tool handler: {name}")

    async def snapshot_state(self) -> dict[str, Any]:
        return {
            "pull_requests": _dump(self._prs.values()),
            "issues": _dump(self._issues.values()),
            "repo_files": self._repo_files.copy(),
        }

    async def teardown(self) -> None:
        self._prs.clear()
        self._issues.clear()
        self._repo_files.clear()


class EmailMessage(_Record):
    id: str
    sender: str = ""
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    body: str = ""
    attachments: list[str | dict[str, Any]] = Field(default_factory=list)


class _SentMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    to: list[str]
    subject: str
    body: str
    cc: list[str]
    trust_zone: _Zone


class EmailHoneyEnvironment(_Provider):
    _tools: tuple[_Tool, ...] = (
        _tool(
            "email_list_inbox", "List fixture inbox messages", limit=(int, Field(default=10, ge=0))
        ),
        _tool("email_read_message", "Read a fixture email", message_id=(str, ...)),
        _tool(
            "email_send_message",
            "Record a simulated outgoing email",
            sink=True,
            to=(list[str], ...),
            subject=(str, ...),
            body=(str, ...),
            cc=(list[str], Field(default_factory=list)),
        ),
    )

    def __init__(self) -> None:
        self._inbox: dict[str, EmailMessage] = {}
        self._outbox: list[_SentMessage] = []
        self._domains: set[str] = set()

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        self._inbox = _records(
            EmailMessage,
            rendered_state.get("emails", rendered_state.get("inbox", [])),
            lambda message: message.id,
            "emails",
        )
        try:
            domains = _STRING_LIST.validate_python(
                rendered_state.get("internal_domains", ["corp.internal"])
            )
        except ValidationError as exc:
            raise ConfigurationError("Invalid internal_domains fixtures") from exc
        self._domains = {host.lower().rstrip(".") for host in domains if host}
        self._outbox.clear()

    def _recipient_zone(self, to: list[str], cc: list[str]) -> _Zone:
        addresses = getaddresses([*to, *cc])
        internal = bool(addresses) and all(
            "@" in address and address.rsplit("@", 1)[1].lower().rstrip(".") in self._domains
            for _, address in addresses
        )
        return "internal_trusted" if internal else "external_untrusted"

    def classify_tool_call(self, schema: ToolSchema, arguments: dict[str, Any]) -> ToolSchema:
        if schema.name != "email_send_message":
            return schema
        try:
            to = _STRING_LIST.validate_python(arguments.get("to"), strict=True)
            cc = _STRING_LIST.validate_python(arguments.get("cc", []), strict=True)
        except ValidationError:
            return schema.model_copy(update={"trust_zone": "external_untrusted"})
        return schema.model_copy(update={"trust_zone": self._recipient_zone(to, cc)})

    def _invoke(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        if name == "email_list_inbox":
            return _list_records(
                "messages",
                list(self._inbox.values())[: args["limit"]],
                lambda message: f"email:{message.id}",
            )
        if name == "email_read_message":
            message = self._inbox.get(args["message_id"])
            return _read(message, f"email:{message.id}") if message else _error("Message not found")
        zone = self._recipient_zone(args["to"], args["cc"])
        self._outbox.append(_SentMessage(**args, trust_zone=zone))
        return _result({"message_id": f"sent:{len(self._outbox)}", "trust_zone": zone})

    async def snapshot_state(self) -> dict[str, Any]:
        return {
            "inbox": _dump(self._inbox.values()),
            "outbox": [message.model_dump() for message in self._outbox],
        }

    async def teardown(self) -> None:
        self._inbox.clear()
        self._outbox.clear()
        self._domains.clear()


class _Refund(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    amount_usd: float = Field(gt=0, allow_inf_nan=False)
    reason: str


class SupportTicket(_Record):
    id: str
    requester_email: str = ""
    priority: str = ""
    subject: str = ""
    description: str = ""
    internal_notes: list[str | dict[str, Any]] = Field(default_factory=list)
    public_replies: list[str] = Field(default_factory=list)
    refunds: list[_Refund] = Field(default_factory=list)
    tenant_id: str = ""
    status: str = "open"


class TicketingHoneyEnvironment(_Provider):
    _tools: tuple[_Tool, ...] = (
        _tool("tickets_list", "List fixture support tickets", status=(str, "open")),
        _tool("tickets_get", "Read a fixture support ticket", ticket_id=(str, ...)),
        _tool(
            "tickets_reply_public",
            "Record a simulated public reply",
            sink=True,
            zone="external_untrusted",
            ticket_id=(str, ...),
            message=(str, ...),
        ),
        _tool(
            "tickets_add_internal_note",
            "Record a simulated internal note",
            ticket_id=(str, ...),
            note=(str, ...),
        ),
        _tool(
            "tickets_issue_refund",
            "Record a simulated refund",
            sink=True,
            ticket_id=(str, ...),
            amount_usd=(float, Field(gt=0)),
            reason=(str, ...),
        ),
    )

    def __init__(self) -> None:
        self._tickets: dict[str, SupportTicket] = {}

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        self._tickets = _records(
            SupportTicket, rendered_state.get("tickets", []), lambda ticket: ticket.id, "tickets"
        )

    def _invoke(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        if name == "tickets_list":
            records = [
                ticket
                for ticket in self._tickets.values()
                if args["status"] in ("all", ticket.status)
            ]
            return _list_records("tickets", records, lambda ticket: f"ticket:{ticket.id}")
        ticket = self._tickets.get(args["ticket_id"])
        if ticket is None:
            return _error("Ticket not found")
        match name:
            case "tickets_get":
                return _read(ticket, f"ticket:{ticket.id}")
            case "tickets_reply_public":
                update = {"public_replies": [*ticket.public_replies, args["message"]]}
            case "tickets_add_internal_note":
                update = {"internal_notes": [*ticket.internal_notes, args["note"]]}
            case "tickets_issue_refund":
                refund = _Refund(amount_usd=args["amount_usd"], reason=args["reason"])
                update = {"refunds": [*ticket.refunds, refund]}
            case _:
                raise ConfigurationError(f"Missing ticket tool handler: {name}")
        self._tickets[ticket.id] = ticket.model_copy(update=update)
        return _result({"ticket_id": ticket.id, "recorded": True})

    async def snapshot_state(self) -> dict[str, Any]:
        return {"tickets": _dump(self._tickets.values())}

    async def teardown(self) -> None:
        self._tickets.clear()


class WikiDoc(_Record):
    doc_id: str
    title: str = ""
    space: str = ""
    content: str = ""
    access_role: str = ""


_WORDS = re.compile(r"\w+")


class WikiRagHoneyEnvironment(_Provider):
    _tools: tuple[_Tool, ...] = (
        _tool("wiki_search", "Search fixture wiki documents", query=(str, ...)),
        _tool("wiki_get_document", "Read a fixture wiki document", doc_id=(str, ...)),
        _tool(
            "wiki_update_document",
            "Update a fixture wiki document",
            sink=True,
            doc_id=(str, ...),
            content=(str, ...),
        ),
    )

    def __init__(self) -> None:
        self._docs: dict[str, WikiDoc] = {}

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        self._docs = _records(
            WikiDoc,
            rendered_state.get("wiki_docs", rendered_state.get("documents", [])),
            lambda doc: doc.doc_id,
            "wiki documents",
        )

    def _invoke(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        if name == "wiki_search":
            terms = set(_WORDS.findall(args["query"].casefold()))
            ranks = [
                (
                    len(
                        terms.intersection(_WORDS.findall(f"{doc.title} {doc.content}".casefold()))
                    ),
                    doc.doc_id,
                )
                for doc in self._docs.values()
            ]
            ranks.sort(key=lambda hit: (-hit[0], hit[1]))
            return _list_records(
                "documents",
                [self._docs[doc_id] for count, doc_id in ranks if count],
                lambda document: f"wiki:{document.doc_id}",
            )
        doc = self._docs.get(args["doc_id"])
        if doc is None:
            return _error("Document not found")
        if name == "wiki_get_document":
            return _read(doc, f"wiki:{doc.doc_id}")
        self._docs[doc.doc_id] = doc.model_copy(update={"content": args["content"]})
        return _result({"doc_id": doc.doc_id, "updated": True})

    async def snapshot_state(self) -> dict[str, Any]:
        return {"wiki_docs": _dump(self._docs.values())}

    async def teardown(self) -> None:
        self._docs.clear()


_READ_SQL = frozenset(
    {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
)
_WRITE_SQL = _READ_SQL | {
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_DROP_VIEW,
    sqlite3.SQLITE_TRANSACTION,
    sqlite3.SQLITE_SAVEPOINT,
}
_SELECT = re.compile(
    r"\A(?:\s++|--[^\n]*(?:\n|\Z)|/\*[\s\S]*?\*/)*+(?:SELECT|WITH)\b", re.IGNORECASE
)


def _authorizer(
    readonly: bool,
) -> Callable[[int, str | None, str | None, str | None, str | None], int]:
    allowed = _READ_SQL if readonly else _WRITE_SQL

    def check(
        action: int,
        first: str | None,
        second: str | None,
        database: str | None,
        trigger: str | None,
    ) -> int:
        if action not in allowed or database not in {None, "main"}:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and (second or "").lower() in {
            "load_extension",
            "readfile",
            "writefile",
        }:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    return check


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _seed_rows(db: sqlite3.Connection, rows: dict[str, Any]) -> None:
    for table, records in rows.items():
        if not isinstance(records, list):
            raise ConfigurationError(f"Expected a list of seed rows for {table}")
        for record in records:
            if not isinstance(record, dict) or not record:
                raise ConfigurationError(f"Expected a nonempty seed row for {table}")
            columns = ", ".join(_quote_identifier(column) for column in record)
            params = ", ".join("?" for _ in record)
            sql = f"INSERT INTO {_quote_identifier(table)} ({columns}) VALUES ({params})"  # noqa: S608 - Quoted identifiers and bound values.
            db.execute(sql, tuple(record.values()))


class DatabaseHoneyEnvironment(_Provider):
    _tools: tuple[_Tool, ...] = (
        _tool("db_query_readonly", "Query the fixture SQLite database read-only", sql=(str, ...)),
        _tool(
            "db_execute_write",
            "Run a statement on the fixture SQLite database",
            sink=True,
            sql=(str, ...),
        ),
    )

    def __init__(self) -> None:
        self._path: Path | None = None

    async def setup(self, sandbox_dir: Path, rendered_state: dict[str, Any]) -> None:
        try:
            spec = DatabaseSpec.model_validate(rendered_state.get("database") or {})
        except ValidationError as exc:
            raise ConfigurationError("Invalid SQLite fixtures") from exc
        path = sandbox_dir.resolve() / "honey.db"
        try:
            path.touch(exist_ok=False)
        except OSError as exc:
            raise ConfigurationError("Could not create fresh honey.db") from exc
        try:
            with closing(sqlite3.connect(path)) as db, db:
                db.set_authorizer(_authorizer(False))
                if spec.schema_sql:
                    db.executescript(spec.schema_sql)
                _seed_rows(db, spec.seed_rows or {})
        except (sqlite3.Error, ConfigurationError, OverflowError) as exc:
            path.unlink(missing_ok=True)
            raise ConfigurationError("Could not seed honey.db") from exc
        self._path = path

    def _database_path(self) -> Path:
        path = self._path
        if path is None or path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ConfigurationError("Expected the trial-local honey.db")
        return path

    def _invoke(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        readonly = name == "db_query_readonly"
        sql: str = args["sql"]
        if readonly and not _SELECT.match(sql):
            return _error("Expected a SELECT or WITH statement")
        try:
            path = self._database_path()
            mode = "ro" if readonly else "rw"
            with closing(sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True)) as db, db:
                db.set_authorizer(_authorizer(readonly))
                cursor = db.execute(sql)
                if cursor.description is None:
                    return _result({"rowcount": cursor.rowcount})
                rows = [
                    [value.hex() if isinstance(value, bytes) else value for value in row]
                    for row in cursor
                ]
                return _result(
                    {"columns": [column[0] for column in cursor.description], "rows": rows}
                )
        except (sqlite3.Error, OSError, ConfigurationError, ValueError):
            return _error("SQLite rejected the statement")

    async def snapshot_state(self) -> dict[str, Any]:
        return {
            "database": {"sha256": hashlib.sha256(self._database_path().read_bytes()).hexdigest()}
        }

    async def teardown(self) -> None:
        self._path = None


def build_composite_environment(
    env_spec: EnvironmentSpec,
    *,
    referenced_tools: Iterable[str] = (),
    approval_policies: Sequence[ApprovalPolicySpec] = (),
    mock_profile_paths: Sequence[str | Path] = (),
    canaries: Mapping[str, GeneratedCanary] | None = None,
    a2a_environment: A2ADelegationEnvironment | None = None,
    browser_environment: BrowserDomTrapEnvironment | None = None,
    trace: TraceWriter | None = None,
    session_id: str = "",
) -> CompositeEnvironment:
    references = set(referenced_tools)
    references.update(rule.tool_name for rule in env_spec.rug_pulls)
    for override in env_spec.tool_overrides:
        name = override.get("tool_name", override.get("name"))
        if isinstance(name, str):
            references.add(name)
    sink = HttpSinkEnvironment()
    workspace = WorkspaceFSEnvironment(sink)
    providers: list[HoneyEnvironment] = [workspace, sink]
    if trace is not None:
        sink.bind_trace(trace, session_id)
        workspace.bind_trace(trace, session_id)
    for prefix, populated, provider in (
        ("git_", bool(env_spec.pull_requests or env_spec.issues), GitPRHoneyEnvironment),
        ("email_", bool(env_spec.emails), EmailHoneyEnvironment),
        ("tickets_", bool(env_spec.tickets), TicketingHoneyEnvironment),
        ("wiki_", bool(env_spec.wiki_docs), WikiRagHoneyEnvironment),
        ("db_", env_spec.database is not None, DatabaseHoneyEnvironment),
    ):
        if populated or any(name.startswith(prefix) for name in references):
            providers.append(provider())
    if approval_policies or "request_human_approval" in references:
        approvals = HumanApprovalEnvironment()
        if trace is not None:
            approvals.bind_trace(trace, session_id)
        providers.append(approvals)
    if env_spec.custom_mock_profiles:
        profiles = load_custom_profiles(env_spec.custom_mock_profiles, mock_profile_paths)
        providers.append(CustomMockProfileEnvironment(profiles, canaries))
    if env_spec.a2a_peers:
        a2a = a2a_environment or A2ADelegationEnvironment()
        if trace is not None:
            a2a.bind_trace(trace, session_id)
        providers.append(a2a)
    if env_spec.browser_pages:
        browser = browser_environment or BrowserDomTrapEnvironment()
        if trace is not None:
            browser.bind_trace(trace, session_id)
        providers.append(browser)
    return CompositeEnvironment(providers)
