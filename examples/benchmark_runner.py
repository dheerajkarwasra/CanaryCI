"""Measure wall-clock time for a fixed, offline scripted suite."""

import argparse
import asyncio
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from canary_ci.core.errors import ConfigurationError
from canary_ci.core.models import AdapterConfig, CanaryConfig
from canary_ci.runner.suite_runner import SuiteRunner
from canary_ci.scenarios import discover_scenarios


async def benchmark(samples: int) -> None:
    scenarios = discover_scenarios(["builtin:all"])
    print(f"{len(scenarios)} scenarios, 1 trial per scenario, concurrency 1")
    elapsed_ms: list[float] = []
    runner = SuiteRunner()
    for index in range(samples + 1):
        with TemporaryDirectory(prefix="canary_benchmark_") as artifacts:
            config = CanaryConfig(
                version="1",
                adapter=AdapterConfig(kind="scripted", mode="benign"),
                seed="runner-benchmark",
                concurrency=1,
                artifacts_dir=artifacts,
            )
            start = perf_counter()
            result = await runner.run(scenarios, config, trials_override=1)
            duration = 1000 * (perf_counter() - start)
            if not result.passed or len(result.outcomes) != len(scenarios):
                raise ConfigurationError("The benchmark suite did not complete successfully")
            if index:  # Exclude the warm-up sample.
                elapsed_ms.append(duration)
                print(f"Sample {index}   {duration:.1f} ms")
    print(f"Median suite duration   {median(elapsed_ms):.1f} ms")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=5, help="timed runs after one warm-up")
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")
    asyncio.run(benchmark(args.samples))


if __name__ == "__main__":
    main()
