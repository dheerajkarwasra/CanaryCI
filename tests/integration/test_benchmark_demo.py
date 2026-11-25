import os
import subprocess
import sys
from pathlib import Path


def test_benchmark_prints_three_verified_modes(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(repo / "examples" / "run_benchmark_demo.py")],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(repo / "src")},
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "| Unprotected | Partial egress policy | Hardened |" in result.stdout
    row = next(line for line in result.stdout.splitlines() if "40/40" in line)
    cells = row.strip("|").split("|")
    assert cells[0].strip() == "40/40 breached"
    assert 0 < int(cells[1].split("/")[0]) < 40
    assert cells[2].strip() == "0/40 breached"


def test_runner_latency_benchmark_measures_fixed_catalog(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(repo / "examples/benchmark_runner.py"), "--samples", "2"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(repo / "src")},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "40 scenarios, 1 trial per scenario, concurrency 1" in result.stdout
    assert "Sample 1" in result.stdout and "Sample 2" in result.stdout
    assert "Median suite duration" in result.stdout
