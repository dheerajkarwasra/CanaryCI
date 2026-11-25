"""Export scenario policy outcomes in JUnit XML for CI test reports."""

import re
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree import ElementTree as ET

from ..core.errors import ConfigurationError
from ..runner.baseline_diff import DiffStatus
from ..runner.suite_runner import ScenarioRunOutcome, SuiteRunSummary

_INVALID_XML = re.compile(r"[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]")


def _xml_text(value: str) -> str:
    return _INVALID_XML.sub("\ufffd", value)


def _failure_details(outcome: ScenarioRunOutcome) -> str:
    lines: list[str] = []
    for trial in outcome.trials:
        breaches = [] if outcome.security_passed else trial.breaches
        if not breaches and not trial.task_failures:
            continue
        lines.append(f"Trial {trial.trial_index} · {trial.trace_path}")
        for breach in breaches:
            sink = f" ({breach.sink_tool})" if breach.sink_tool else ""
            lines.append(f"{breach.breach_kind}{sink}: {breach.summary}")
        lines.extend(f"Task assertion failed: {name}" for name in trial.task_failures)
    return "\n".join(lines)


def write_junit(path: Path, summary: SuiteRunSummary) -> None:
    """Write one testcase per evaluated scenario, using the active run policy."""
    suite = ET.Element("testsuite", name="CanaryCI", tests=str(len(summary.outcomes)), errors="0")
    known_failures = set()
    if summary.new_regressions_only and summary.baseline_diff is not None:
        known_failures = {
            entry.scenario_id
            for entry in summary.baseline_diff.entries
            if entry.status is DiffStatus.KNOWN_FAIL
        }
    duration_ms = 0.0
    failures = skipped = 0
    for outcome in summary.outcomes:
        elapsed = sum(trial.duration_ms for trial in outcome.trials)
        duration_ms += elapsed
        case = ET.SubElement(
            suite,
            "testcase",
            classname="CanaryCI",
            name=_xml_text(outcome.scenario_id),
            time=f"{elapsed / 1000:.6f}",
        )
        if outcome.scenario_id in known_failures:
            ET.SubElement(case, "skipped", message="Known failure in baseline")
            skipped += 1
        elif not outcome.passed:
            reasons = []
            if not outcome.security_passed:
                breached = sum(not trial.passed for trial in outcome.trials)
                reasons.append(f"{breached}/{len(outcome.trials)} trials breached")
            if not outcome.tasks_passed:
                reasons.append("Task-completion assertions failed")
            failure = ET.SubElement(case, "failure", message=". ".join(reasons))
            failure.text = _xml_text(_failure_details(outcome))
            failures += 1
        elif outcome.waived:
            reason = outcome.waiver.reason if outcome.waiver else "Scenario waived"
            ET.SubElement(case, "skipped", message=_xml_text(reason))
            skipped += 1
        ET.SubElement(case, "system-out").text = _xml_text(
            "\n".join(str(trial.trace_path) for trial in outcome.trials)
        )
    suite.set("failures", str(failures))
    suite.set("skipped", str(skipped))
    suite.set("time", f"{duration_ms / 1000:.6f}")
    tree = ET.ElementTree(suite)
    ET.indent(tree)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=path.parent) as staging:
            report = Path(staging) / "report.xml"
            tree.write(report, encoding="utf-8", xml_declaration=True)
            report.replace(path)
    except OSError as exc:
        raise ConfigurationError(f"Cannot write JUnit report at {path}") from exc
