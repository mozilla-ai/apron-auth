from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip integration tests unless ANY_AUTH_INTEGRATION_TESTS=1."""
    if not os.environ.get("ANY_AUTH_INTEGRATION_TESTS"):
        skip_integration = pytest.mark.skip(reason="Set ANY_AUTH_INTEGRATION_TESTS=1 to run")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)
