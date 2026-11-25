from tempfile import TemporaryDirectory

import pytest
from hypothesis.configuration import set_hypothesis_home_dir


def pytest_configure(config: pytest.Config) -> None:
    # Hypothesis caches source constants during collection, before fixtures run.
    storage = TemporaryDirectory(prefix="canary_hypothesis_")
    set_hypothesis_home_dir(storage.name)
    config.add_cleanup(storage.cleanup)
    config.add_cleanup(lambda: set_hypothesis_home_dir(None))
