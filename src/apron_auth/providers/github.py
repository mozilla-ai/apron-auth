"""GitHub OAuth provider preset and revocation handler."""

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

_GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class GitHubRevocationHandler:
    """GitHub OAuth grant revocation via authenticated DELETE.

    Targets ``DELETE /applications/{client_id}/grant``, which removes
    the user's entire authorization for the OAuth app so that a
    subsequent re-auth presents a fresh consent screen — required for
    scope-reduction flows. The alternative ``/token`` endpoint only
    invalidates a single access token and re-auth silently reuses the
    existing grant.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke the GitHub OAuth grant at the configured revocation endpoint."""
        if config.revocation_url is None:
            msg = "revocation_url is required but not set in ProviderConfig"
            raise ValueError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        async with httpx.AsyncClient() as client:
            return await self._send(client, token, revocation_url, config)

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status."""
        try:
            response = await client.request(
                "DELETE",
                revocation_url,
                auth=(config.client_id, config.client_secret.get_secret_value()),
                headers=_GITHUB_API_HEADERS,
                json={"access_token": token},
            )
        except httpx.RequestError as exc:
            raise RevocationError(str(exc)) from exc
        # 204: grant removed. 404: already gone — idempotent re-disconnect.
        if response.status_code in (204, 404):
            return True
        # 422: validation failed or spam-throttled per GitHub docs. Treat
        # as a soft failure so callers can continue with local cleanup.
        if response.status_code == 422:
            logger.warning(
                "GitHub grant revocation returned 422 (validation failed "
                "or spam-throttled); the grant may still exist at GitHub"
            )
            return False
        logger.warning(
            "GitHub grant revocation returned unexpected status %s",
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
    """Create a GitHub OAuth provider configuration."""
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        revocation_url=f"https://api.github.com/applications/{client_id}/grant",
        redirect_uri=redirect_uri,
        scopes=scopes,
        extra_params=extra_params or {},
    )
    return config, GitHubRevocationHandler()
