"""Integration tests for GitHub OAuth against real endpoints.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... GITHUB_REFRESH_TOKEN=... \
    uv run pytest -m integration -k github -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import github

pytestmark = pytest.mark.integration


@pytest.fixture()
def github_env() -> dict[str, str]:
    """Retrieve GitHub credentials from environment or skip."""
    client_id = os.environ.get("GITHUB_CLIENT_ID", "")
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "")
    refresh_token = os.environ.get("GITHUB_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and GITHUB_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestGitHubRefresh:
    async def test_refresh_returns_access_token(self, github_env: dict[str, str]):
        config, _ = github.preset(
            client_id=github_env["client_id"],
            client_secret=github_env["client_secret"],
            scopes=["repo"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(github_env["refresh_token"])
        assert tokens.access_token


class TestGitHubRevocation:
    async def test_revoke_access_token(self, github_env: dict[str, str]):
        """Refresh to get a fresh access token, then revoke it."""
        config, handler = github.preset(
            client_id=github_env["client_id"],
            client_secret=github_env["client_secret"],
            scopes=["repo"],
        )
        client = OAuthClient(config, revocation_handler=handler)
        tokens = await client.refresh_token(github_env["refresh_token"])
        result = await client.revoke_token(tokens.access_token)
        assert result is True
