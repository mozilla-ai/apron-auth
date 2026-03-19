"""Integration tests for Microsoft OAuth against real endpoints.

Microsoft does not have a revocation endpoint, so only refresh is tested.

Skipped by default. To run::

    APRON_AUTH_INTEGRATION_TESTS=1 \
    MICROSOFT_CLIENT_ID=... MICROSOFT_CLIENT_SECRET=... MICROSOFT_REFRESH_TOKEN=... \
    uv run pytest -m integration -k microsoft -v
"""

from __future__ import annotations

import os

import pytest

from apron_auth.client import OAuthClient
from apron_auth.providers import microsoft

pytestmark = pytest.mark.integration


@pytest.fixture()
def microsoft_env() -> dict[str, str]:
    """Retrieve Microsoft credentials from environment or skip."""
    client_id = os.environ.get("MICROSOFT_CLIENT_ID", "")
    client_secret = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
    refresh_token = os.environ.get("MICROSOFT_REFRESH_TOKEN", "")
    if not all([client_id, client_secret, refresh_token]):
        pytest.skip("MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, and MICROSOFT_REFRESH_TOKEN required")
    return {"client_id": client_id, "client_secret": client_secret, "refresh_token": refresh_token}


class TestMicrosoftRefresh:
    async def test_refresh_returns_access_token(self, microsoft_env: dict[str, str]):
        config, _ = microsoft.preset(
            client_id=microsoft_env["client_id"],
            client_secret=microsoft_env["client_secret"],
            scopes=["offline_access"],
        )
        client = OAuthClient(config)
        tokens = await client.refresh_token(microsoft_env["refresh_token"])
        assert tokens.access_token
