"""Google OAuth provider preset and revocation handler."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from any_auth.models import ProviderConfig

if TYPE_CHECKING:
    from any_auth.protocols import RevocationHandler


class GoogleRevocationHandler:
    """Google token revocation via POST with token as query parameter."""

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at Google's revocation endpoint."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.revocation_url,
                params={"token": token},
            )
        return response.is_success


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Google OAuth provider configuration.

    Default extra_params include access_type=offline and prompt=consent
    for offline access.
    """
    defaults = {"access_type": "offline", "prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        revocation_url="https://oauth2.googleapis.com/revoke",
        redirect_uri=redirect_uri,
        scopes=scopes,
        extra_params=defaults,
    )
    return config, GoogleRevocationHandler()
