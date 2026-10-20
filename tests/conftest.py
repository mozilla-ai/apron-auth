from __future__ import annotations

import os
from dataclasses import replace

import pytest
from support import VaryFacts

from apron_auth.models import Provider


@pytest.fixture
def vary_facts(monkeypatch: pytest.MonkeyPatch) -> VaryFacts:
    """Return the callable that varies a provider member's facts.

    A member's facts are read-only, so a test that needs a provider whose facts differ from the
    shipped ones asks for them here rather than assigning to the member.

    Returns:
        The callable, which takes a member and the facts to change.
    """

    def vary(provider: Provider, **changes: object) -> None:
        monkeypatch.setattr(provider, "_facts", replace(provider._facts, **changes))

    return vary


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
