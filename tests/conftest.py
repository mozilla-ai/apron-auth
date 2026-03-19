from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip integration tests unless explicitly opted in.

    Integration tests are marked with @pytest.mark.integration and require
    provider credentials via environment variables. They are skipped by
    default in CI and local runs.

    To run integration tests::

        APRON_AUTH_INTEGRATION_TESTS=1 GOOGLE_CLIENT_ID=... uv run pytest -m integration
    """
    skip_integration = pytest.mark.skip(reason="set APRON_AUTH_INTEGRATION_TESTS=1 and provider credentials to run")
    for item in items:
        if "integration" in item.keywords and not os.environ.get("APRON_AUTH_INTEGRATION_TESTS"):
            item.add_marker(skip_integration)
