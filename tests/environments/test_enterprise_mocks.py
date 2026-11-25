from pathlib import Path
from typing import Any

import pytest

from canary_ci.core.models import EnvironmentSpec
from canary_ci.environments.base import HoneyEnvironment
from canary_ci.environments.enterprise_mocks import (
    DatabaseHoneyEnvironment,
    EmailHoneyEnvironment,
    GitPRHoneyEnvironment,
    TicketingHoneyEnvironment,
    WikiRagHoneyEnvironment,
    build_composite_environment,
)


@pytest.mark.parametrize(
    ("provider", "state", "tool", "args", "source_id"),
    [
        (
            GitPRHoneyEnvironment,
            {"pull_requests": [{"id": 104, "body": "fixture", "trust_level": "untrusted"}]},
            "git_get_pull_request",
            {"pr_number": 104},
            "pr:104",
        ),
        (
            GitPRHoneyEnvironment,
            {"issues": [{"id": 205, "body": "fixture", "trust_level": "untrusted"}]},
            "git_get_issue",
            {"issue_number": 205},
            "issue:205",
        ),
        (
            EmailHoneyEnvironment,
            {"emails": [{"id": "msg_01", "body": "fixture", "trust_level": "untrusted"}]},
            "email_read_message",
            {"message_id": "msg_01"},
            "email:msg_01",
        ),
        (
            TicketingHoneyEnvironment,
            {"tickets": [{"id": "ticket_1", "description": "fixture", "trust_level": "untrusted"}]},
            "tickets_get",
            {"ticket_id": "ticket_1"},
            "ticket:ticket_1",
        ),
        (
            WikiRagHoneyEnvironment,
            {"wiki_docs": [{"doc_id": "doc_1", "content": "fixture", "trust_level": "untrusted"}]},
            "wiki_get_document",
            {"doc_id": "doc_1"},
            "wiki:doc_1",
        ),
        (
            WikiRagHoneyEnvironment,
            {"wiki_docs": [{"doc_id": "doc_1", "content": "fixture", "trust_level": "untrusted"}]},
            "wiki_search",
            {"query": "fixture"},
            "wiki:doc_1",
        ),
    ],
)
async def test_enterprise_reads_preserve_untrusted_source(
    tmp_path: Path,
    provider: type[HoneyEnvironment],
    state: dict[str, Any],
    tool: str,
    args: dict[str, Any],
    source_id: str,
) -> None:
    environment = provider()
    await environment.setup(tmp_path, state)

    result = await environment.call_tool(tool, args, 0)

    assert not result.is_error
    assert "fixture" in result.content
    assert result.contains_untrusted_content
    assert result.untrusted_source_id == source_id
    await environment.teardown()


async def test_wiki_ranks_overlap_and_persists_updates(tmp_path: Path) -> None:
    wiki = WikiRagHoneyEnvironment()
    await wiki.setup(
        tmp_path,
        {
            "wiki_docs": [
                {"doc_id": "z", "content": "Quarterly report"},
                {"doc_id": "a", "content": "quarterly"},
                {"doc_id": "b", "content": "Quarterly report"},
            ]
        },
    )

    ranked = await wiki.call_tool("wiki_search", {"query": "QUARTERLY report"}, 0)
    assert ranked.structured_data is not None
    assert [doc["doc_id"] for doc in ranked.structured_data["documents"]] == ["b", "z", "a"]
    assert not ranked.contains_untrusted_content

    await wiki.call_tool("wiki_update_document", {"doc_id": "b", "content": "Updated"}, 1)
    read = await wiki.call_tool("wiki_get_document", {"doc_id": "b"}, 2)
    assert read.structured_data is not None
    assert read.structured_data["content"] == "Updated"


async def test_git_comments_and_merge_change_trial_state(tmp_path: Path) -> None:
    git = GitPRHoneyEnvironment()
    await git.setup(tmp_path, {"pull_requests": [{"id": 104, "diff": "diff fixture"}]})
    assert not (
        await git.call_tool("git_post_pr_comment", {"pr_number": 104, "body": "Reviewed"}, 1)
    ).is_error
    assert not (await git.call_tool("git_merge_pull_request", {"pr_number": 104}, 2)).is_error

    pr = await git.call_tool("git_get_pull_request", {"pr_number": 104}, 3)
    assert pr.structured_data is not None
    assert pr.structured_data["state"] == "merged"
    assert "Reviewed" in pr.content
    assert "diff fixture" in pr.content


async def test_email_classifies_all_recipients_and_records_outbox(tmp_path: Path) -> None:
    email = EmailHoneyEnvironment()
    await email.setup(tmp_path, {"internal_domains": ["corp.internal"]})
    msg = {"to": ["staff@corp.internal"], "subject": "Fixture", "body": "Message"}
    inside = await email.call_tool("email_send_message", msg, 1)
    outside = await email.call_tool(
        "email_send_message", {**msg, "cc": ["audit@fixture.invalid"]}, 2
    )

    assert inside.structured_data is not None and outside.structured_data is not None
    assert inside.structured_data["trust_zone"] == "internal_trusted"
    assert outside.structured_data["trust_zone"] == "external_untrusted"
    assert len((await email.snapshot_state())["outbox"]) == 2


async def test_ticket_actions_record_public_private_and_refund_state(tmp_path: Path) -> None:
    tickets = TicketingHoneyEnvironment()
    await tickets.setup(tmp_path, {"tickets": [{"id": "t1"}]})
    for tool, args in [
        ("tickets_reply_public", {"message": "Reply"}),
        ("tickets_add_internal_note", {"note": "Note"}),
        ("tickets_issue_refund", {"amount_usd": 25.0, "reason": "Fixture"}),
    ]:
        result = await tickets.call_tool(tool, {"ticket_id": "t1", **args}, 1)
        assert not result.is_error

    ticket = (await tickets.snapshot_state())["tickets"][0]
    assert ticket["public_replies"] == ["Reply"]
    assert ticket["internal_notes"] == ["Note"]
    assert ticket["refunds"] == [{"amount_usd": 25.0, "reason": "Fixture"}]


async def test_sqlite_readonly_and_write_persistence(tmp_path: Path) -> None:
    database = DatabaseHoneyEnvironment()
    await database.setup(
        tmp_path,
        {
            "database": {
                "schema_sql": "CREATE TABLE inventory (id INTEGER PRIMARY KEY, stock INTEGER)",
                "seed_rows": {"inventory": [{"id": 1, "stock": 4}]},
            }
        },
    )
    assert (tmp_path / "honey.db").is_file()
    before = await database.snapshot_state()

    for sql in [
        "UPDATE inventory SET stock = 9",
        "WITH item AS (SELECT 1) UPDATE inventory SET stock = 9",
    ]:
        assert (await database.call_tool("db_query_readonly", {"sql": sql}, 0)).is_error
    initial = await database.call_tool(
        "db_query_readonly",
        {"sql": "WITH item AS (SELECT stock FROM inventory) SELECT * FROM item"},
        1,
    )
    assert initial.structured_data == {"columns": ["stock"], "rows": [[4]]}
    assert await database.snapshot_state() == before

    updated = await database.call_tool(
        "db_execute_write", {"sql": "UPDATE inventory SET stock = 7 WHERE id = 1"}, 2
    )
    assert not updated.is_error
    after = await database.call_tool("db_query_readonly", {"sql": "SELECT stock FROM inventory"}, 3)
    assert after.structured_data == {"columns": ["stock"], "rows": [[7]]}
    assert await database.snapshot_state() != before


def test_factory_mounts_populated_and_referenced_providers() -> None:
    env = EnvironmentSpec(wiki_docs=[{"doc_id": "doc"}])
    composite = build_composite_environment(
        env, referenced_tools=["email_send_message", "request_human_approval"]
    )
    names = {tool.name for tool in composite.list_tools()}

    assert {
        "fs_read_file",
        "http_fetch",
        "wiki_search",
        "email_send_message",
        "request_human_approval",
    } <= names
    assert {"git_list_pull_requests", "tickets_list", "db_execute_write"}.isdisjoint(names)
