"""Integration tests for Linear OAuth against real endpoints.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    LINEAR_CLIENT_ID=... LINEAR_CLIENT_SECRET=... LINEAR_REFRESH_TOKEN=... \
    uv run pytest -m integration -k linear -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import linear

pytestmark = pytest.mark.integration


@pytest.fixture()
def linear_env() -> dict[str, str]:
    """Retrieve Linear credentials from environment or skip."""
    client_id = os.environ.get("LINEAR_CLIENT_ID", "")
    client_secret = os.environ.get("LINEAR_CLIENT_SECRET", "")
    refresh_token = os.environ.get("LINEAR_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("LINEAR_CLIENT_ID, LINEAR_CLIENT_SECRET, and LINEAR_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestLinearRefresh:
    async def test_refresh_returns_access_token(self, linear_env: dict[str, str]):
        config, _ = linear.preset(
            client_id=linear_env["client_id"],
            client_secret=linear_env["client_secret"],
            scopes=["read"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(linear_env["refresh_token"])
        assert tokens.access_token


class TestLinearRevocation:
    async def test_revoke_access_token(self, linear_env: dict[str, str]):
        """Refresh to get a fresh access token, then revoke it."""
        config, handler = linear.preset(
            client_id=linear_env["client_id"],
            client_secret=linear_env["client_secret"],
            scopes=["read"],
        )
        client = OAuthClient(config, revocation_handler=handler)
        tokens = await client.refresh_token(linear_env["refresh_token"])
        result = await client.revoke_token(tokens.access_token)
        assert result is True
