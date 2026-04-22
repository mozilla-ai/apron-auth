"""Notion OAuth provider preset and revocation handler."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler

logger = logging.getLogger(__name__)

NOTION_REVOCATION_URL = "https://api.notion.com/v1/oauth/revoke"


class NotionRevocationHandler:
    """Notion token revocation via POST with JSON body and Basic auth.

    Notion's revoke endpoint returns 200 on success and 400 when the token
    is already invalid; both are treated as successful (idempotent) outcomes.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a Notion access token."""
        if self._client is not None:
            return await self._send(self._client, token, config)
        async with httpx.AsyncClient() as client:
            return await self._send(client, token, config)

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status."""
        try:
            response = await client.post(
                NOTION_REVOCATION_URL,
                json={"token": token},
                auth=(config.client_id, config.client_secret.get_secret_value()),
            )
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        if response.status_code in (200, 400):
            return True
        logger.warning(
            "Notion revocation returned unexpected status %d",
            response.status_code,
        )
        return False


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Notion OAuth provider configuration.

    Notion uses client_secret_basic auth. Revocation targets the hardcoded
    endpoint https://api.notion.com/v1/oauth/revoke.
    """
    defaults = {"owner": "user"}
    if extra_params:
        defaults.update(extra_params)

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://api.notion.com/v1/oauth/authorize",
        token_url="https://api.notion.com/v1/oauth/token",
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_endpoint_auth_method="client_secret_basic",
        extra_params=defaults,
    )
    return config, NotionRevocationHandler()
