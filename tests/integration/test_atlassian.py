"""Integration tests for Atlassian OAuth against real endpoints.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    ATLASSIAN_CLIENT_ID=... ATLASSIAN_CLIENT_SECRET=... ATLASSIAN_REFRESH_TOKEN=... \
    uv run pytest -m integration -k atlassian -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import atlassian

pytestmark = pytest.mark.integration


@pytest.fixture()
def atlassian_env() -> dict[str, str]:
    """Retrieve Atlassian credentials from environment or skip."""
    client_id = os.environ.get("ATLASSIAN_CLIENT_ID", "")
    client_secret = os.environ.get("ATLASSIAN_CLIENT_SECRET", "")
    refresh_token = os.environ.get("ATLASSIAN_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("ATLASSIAN_CLIENT_ID, ATLASSIAN_CLIENT_SECRET, and ATLASSIAN_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestAtlassianRefresh:
    async def test_refresh_returns_access_token(self, atlassian_env: dict[str, str]):
        config, _ = atlassian.preset(
            client_id=atlassian_env["client_id"],
            client_secret=atlassian_env["client_secret"],
            scopes=["read:jira-work"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(atlassian_env["refresh_token"])
        assert tokens.access_token


class TestAtlassianRevocation:
    async def test_revoke_access_token(self, atlassian_env: dict[str, str]):
        """Refresh to get a fresh access token, then revoke it."""
        config, handler = atlassian.preset(
            client_id=atlassian_env["client_id"],
            client_secret=atlassian_env["client_secret"],
            scopes=["read:jira-work"],
        )
        client = OAuthClient(config, revocation_handler=handler)
        tokens = await client.refresh_token(atlassian_env["refresh_token"])
        result = await client.revoke_token(tokens.access_token)
        assert result is True
