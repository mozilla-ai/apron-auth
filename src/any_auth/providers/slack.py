"""Slack OAuth provider preset and revocation handler."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from any_auth.models import ProviderConfig

if TYPE_CHECKING:
    from any_auth.protocols import RevocationHandler


class SlackRevocationHandler:
    """Slack token revocation via GET with token as query parameter."""

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at Slack's revocation endpoint."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                config.revocation_url,
                params={"token": token},
            )
        if not response.is_success:
            return False
        data = response.json()
        return data.get("ok", False)


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Slack OAuth provider configuration."""
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://slack.com/oauth/v2/authorize",
        token_url="https://slack.com/api/oauth.v2.access",
        revocation_url="https://slack.com/api/auth.revoke",
        redirect_uri=redirect_uri,
        scopes=scopes,
        scope_separator=",",
        extra_params=extra_params or {},
    )
    return config, SlackRevocationHandler()
