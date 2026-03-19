"""Integration tests for Salesforce OAuth against real endpoints.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    SALESFORCE_CLIENT_ID=... SALESFORCE_CLIENT_SECRET=... SALESFORCE_REFRESH_TOKEN=... \
    uv run pytest -m integration -k salesforce -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import salesforce

pytestmark = pytest.mark.integration


@pytest.fixture()
def salesforce_env() -> dict[str, str]:
    """Retrieve Salesforce credentials from environment or skip."""
    client_id = os.environ.get("SALESFORCE_CLIENT_ID", "")
    client_secret = os.environ.get("SALESFORCE_CLIENT_SECRET", "")
    refresh_token = os.environ.get("SALESFORCE_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("SALESFORCE_CLIENT_ID, SALESFORCE_CLIENT_SECRET, and SALESFORCE_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestSalesforceRefresh:
    async def test_refresh_returns_access_token(self, salesforce_env: dict[str, str]):
        config, _ = salesforce.preset(
            client_id=salesforce_env["client_id"],
            client_secret=salesforce_env["client_secret"],
            scopes=["api"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(salesforce_env["refresh_token"])
        assert tokens.access_token


class TestSalesforceRevocation:
    async def test_revoke_access_token(self, salesforce_env: dict[str, str]):
        """Refresh to get a fresh access token, then revoke it."""
        config, handler = salesforce.preset(
            client_id=salesforce_env["client_id"],
            client_secret=salesforce_env["client_secret"],
            scopes=["api"],
        )
        client = OAuthClient(config, revocation_handler=handler)
        tokens = await client.refresh_token(salesforce_env["refresh_token"])
        result = await client.revoke_token(tokens.access_token)
        assert result is True
