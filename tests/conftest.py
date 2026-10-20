from __future__ import annotations

import os
from dataclasses import replace
from typing import Protocol

import pytest

from apron_auth.models import Provider


class VaryFacts(Protocol):
    """Give a provider member different facts for the test that asks."""

    def __call__(self, provider: Provider, **changes: object) -> None:
        """Replace the named facts of ``provider`` for the duration of one test.

        Args:
            provider: The member whose facts differ in this test.
            changes: The facts to replace, named as :class:`~apron_auth.models.ProviderFacts` names them.
        """
        ...


@pytest.fixture
def vary_facts(monkeypatch: pytest.MonkeyPatch) -> VaryFacts:
    """Return the callable that varies a provider member's facts.

    A member's facts are read-only, so a test that needs a provider whose facts differ from the
    shipped ones asks for them here rather than assigning to the member.

    Returns:
        The callable, which takes a member and the facts to change.
    """

    def vary(provider: Provider, **changes: object) -> None:
        monkeypatch.setattr(provider, "_facts", replace(provider._facts, **changes))  # noqa: SLF001

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
