"""Integration tests for Slack OAuth against real endpoints.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    SLACK_CLIENT_ID=... SLACK_CLIENT_SECRET=... SLACK_REFRESH_TOKEN=... \
    uv run pytest -m integration -k slack -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import slack

pytestmark = pytest.mark.integration


@pytest.fixture()
def slack_env() -> dict[str, str]:
    """Retrieve Slack credentials from environment or skip."""
    client_id = os.environ.get("SLACK_CLIENT_ID", "")
    client_secret = os.environ.get("SLACK_CLIENT_SECRET", "")
    refresh_token = os.environ.get("SLACK_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, and SLACK_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestSlackRefresh:
    async def test_refresh_returns_access_token(self, slack_env: dict[str, str]):
        config, _ = slack.preset(
            client_id=slack_env["client_id"],
            client_secret=slack_env["client_secret"],
            scopes=["channels:read"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(slack_env["refresh_token"])
        assert tokens.access_token


class TestSlackRevocation:
    async def test_revoke_access_token(self, slack_env: dict[str, str]):
        """Refresh to get a fresh access token, then revoke it."""
        config, handler = slack.preset(
            client_id=slack_env["client_id"],
            client_secret=slack_env["client_secret"],
            scopes=["channels:read"],
        )
        client = OAuthClient(config, revocation_handler=handler)
        tokens = await client.refresh_token(slack_env["refresh_token"])
        result = await client.revoke_token(tokens.access_token)
        assert result is True
