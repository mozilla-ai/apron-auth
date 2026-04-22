"""HubSpot OAuth provider preset and revocation handler."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from apron_auth.errors import RevocationError
from apron_auth.models import ProviderConfig

if TYPE_CHECKING:
    from apron_auth.protocols import RevocationHandler


logger = logging.getLogger(__name__)


class HubSpotRevocationHandler:
    """HubSpot token revocation via DELETE on the refresh-token path.

    HubSpot revokes by refresh token, not access token. Callers must
    pass the refresh token as the ``token`` argument to :meth:`revoke`.

    Revoking invalidates only the specific refresh token (and any access
    tokens issued from it). It does not uninstall the app or remove the
    portal-level OAuth grant, so a subsequent reauthorization flow will
    reuse the existing grant without presenting a fresh consent screen.
    Full grant removal requires a manual action in the HubSpot portal.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a HubSpot refresh token.

        The ``token`` argument must be the refresh token issued by
        HubSpot. Returns True on 204 (revoked) or 404 (already gone —
        idempotent). Returns False for other non-success statuses.
        Raises :class:`RevocationError` on network failure.

        The ``config`` argument is accepted to satisfy the
        :class:`~apron_auth.protocols.RevocationHandler` protocol but
        is not used: HubSpot's revocation endpoint is fixed and takes
        no client credentials.
        """
        del config
        encoded = quote(token, safe="")
        url = f"https://api.hubapi.com/oauth/v1/refresh-tokens/{encoded}"
        if self._client is not None:
            return await self._send(self._client, url)
        async with httpx.AsyncClient() as client:
            return await self._send(client, url)

    async def _send(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            response = await client.delete(url)
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        if response.status_code in (204, 404):
            return True
        logger.warning(
            "HubSpot revocation returned unexpected status %s",
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
    """Create a HubSpot OAuth provider configuration.

    HubSpot uses ``client_secret_post`` token-endpoint authentication
    and a non-standard revocation endpoint that takes the refresh
    token in the URL path. The returned :class:`HubSpotRevocationHandler`
    expects the refresh token (not the access token) as the ``token``
    argument to :meth:`~HubSpotRevocationHandler.revoke`. See the
    handler docstring for the consent-screen caveat on reauthorization.
    """
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://app.hubspot.com/oauth/authorize",
        token_url="https://api.hubapi.com/oauth/v1/token",
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_endpoint_auth_method="client_secret_post",
        extra_params=extra_params or {},
    )
    return config, HubSpotRevocationHandler()
