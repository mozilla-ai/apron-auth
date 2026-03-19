"""Integration tests for Google OAuth against real endpoints.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... GOOGLE_REFRESH_TOKEN=... \
    uv run pytest -m integration -k google -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import google

pytestmark = pytest.mark.integration


@pytest.fixture()
def google_env() -> dict[str, str]:
    """Retrieve Google credentials from environment or skip."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    refresh_token = os.environ.get("GOOGLE_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestGoogleRefresh:
    async def test_refresh_returns_access_token(self, google_env: dict[str, str]):
        config, _ = google.preset(
            client_id=google_env["client_id"],
            client_secret=google_env["client_secret"],
            scopes=["openid", "email"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(google_env["refresh_token"])
        assert tokens.access_token
        assert tokens.token_type.lower() == "bearer"

    async def test_refresh_returns_expiry(self, google_env: dict[str, str]):
        config, _ = google.preset(
            client_id=google_env["client_id"],
            client_secret=google_env["client_secret"],
            scopes=["openid", "email"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(google_env["refresh_token"])
        assert tokens.expires_in is not None
        assert tokens.expires_in > 0


class TestGoogleRevocation:
    async def test_revoke_access_token(self, google_env: dict[str, str]):
        """Refresh to get a fresh access token, then revoke it."""
        config, handler = google.preset(
            client_id=google_env["client_id"],
            client_secret=google_env["client_secret"],
            scopes=["openid", "email"],
        )
        client = OAuthClient(config, revocation_handler=handler)
        tokens = await client.refresh_token(google_env["refresh_token"])
        result = await client.revoke_token(tokens.access_token)
        assert result is True
