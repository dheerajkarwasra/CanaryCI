"""Render trial results and replay timelines in the terminal."""

import shlex

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..runner.suite_runner import ReplayReport, SuiteRunSummary
from . import _STAGE_LABELS


def render_suite_summary(summary: SuiteRunSummary, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title=f"CanaryCI run {summary.run_id}")
    for column in ("Scenario", "OWASP", "Severity", "Trials", "Status", "Duration", "Breach"):
        table.add_column(column)
    show_tasks = any(
        trial.task_completed is not None for case in summary.outcomes for trial in case.trials
    )
    if show_tasks:
        table.add_column("Task completion")
    for outcome in summary.outcomes:
        breaches = [breach for trial in outcome.trials for breach in trial.breaches]
        if outcome.waived and outcome.tasks_passed:
            status = Text("WAIVED", style="yellow")
        elif not outcome.passed:
            status = Text("FAIL", style="red")
        elif any(trial.mitigated_by == "defense_proxy" for trial in outcome.trials):
            status = Text("MITIGATED", style="cyan")
        else:
            status = Text("PASS", style="green")
        duration = sum(trial.duration_ms for trial in outcome.trials)
        trial_count = str(len(outcome.trials))
        if (stats := outcome.stats) and stats.total_trials > 1:
            trial_count = (
                f"Breached {stats.breached_trials}/{stats.total_trials}\n"
                f"Rate {stats.raw_breach_rate:.2%} · secure^{stats.total_trials} "
                f"{stats.secure_hat_k:.2%}"
            )
        task_cells: list[Text] = []
        if show_tasks:
            checked = [trial for trial in outcome.trials if trial.task_completed is not None]
            failed_ids = sorted({name for trial in checked for name in trial.task_failures})
            task_cells.append(
                Text(", ".join(failed_ids) if failed_ids else "PASS" if checked else "—")
            )
        table.add_row(
            Text(outcome.scenario_id),
            outcome.owasp_category or "",
            outcome.severity or "",
            trial_count,
            status,
            f"{duration:.1f} ms",
            Text(breaches[0].summary if breaches else ""),
            *task_cells,
        )
    console.print(table)


def render_provenance_trees(summary: SuiteRunSummary, console: Console | None = None) -> None:
    console = console or Console()
    for outcome in summary.outcomes:
        for trial in outcome.trials:
            for chain in trial.provenance_chains:
                tree = Tree(Text(f"{outcome.scenario_id} · {chain.owasp_category}"))
                branch = tree
                for node in chain.nodes:
                    branch = branch.add(Text(f"{_STAGE_LABELS[node.stage]} · {node.summary}"))
                tree.add(Text(f"Remediation · {chain.remediation_hint}"))
                tree.add(Text(f"canary-ci replay {shlex.quote(str(trial.trace_path))}"))
                console.print(tree)


def render_replay_transcript(report: ReplayReport, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title=f"Replay · {report.scenario.id}")
    for column in ("Session", "Turn", "Actor", "Event", "Tool", "Content"):
        table.add_column(column)
    for event in report.events:
        value = event.payload.get("content", event.payload.get("arguments", ""))
        table.add_row(
            Text(event.session_id),
            str(event.turn_index),
            event.actor,
            event.event_type,
            Text(event.tool_name or ""),
            Text(str(value)),
        )
    console.print(table)
    if report.task_completed is not None:
        result = "PASS" if report.task_completed else "FAIL · " + ", ".join(report.task_failures)
        console.print(Text(f"Task completion · {result}"))
    for chain in report.provenance_chains:
        tree = Tree(Text(f"{chain.owasp_category} · {chain.breach_kind}"))
        for node in chain.nodes:
            tree.add(Text(f"{_STAGE_LABELS[node.stage]} · {node.summary}"))
        console.print(tree)
