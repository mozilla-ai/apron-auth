"""Atlassian OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Atlassian does not document an
OAuth revoke endpoint that removes the user's portal-level grant.
Token revocation alone (where supported) does not clear the entry
under ``id.atlassian.com/manage-profile/apps``, so consumers must
surface a deep link to that page for manual removal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_ATLASSIAN_USERINFO_URL = "https://api.atlassian.com/me"
_ATLASSIAN_IDENTITY_HOST_SUFFIXES = ("auth.atlassian.com",)


class AtlassianIdentityHandler:
    """Fetch identity fields from Atlassian's User Identity API.

    Requires the ``read:me`` OAuth scope and that the "User Identity
    API" is enabled on the OAuth app in the Atlassian developer
    console — without that toggle, ``GET /me`` returns 401 even with a
    valid access token.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using an Atlassian access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _ATLASSIAN_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Atlassian identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Atlassian identity response: {exc}") from exc

        return IdentityProfile(
            subject=payload.get("account_id"),
            email=payload.get("email"),
            email_verified=None,
            name=payload.get("name"),
            username=payload.get("nickname"),
            avatar_url=payload.get("picture"),
            raw=payload,
        )


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Atlassian identity handler when config matches Atlassian hosts."""
    if oauth_hosts_match(config, _ATLASSIAN_IDENTITY_HOST_SUFFIXES):
        return AtlassianIdentityHandler()
    return None


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="offline_access",
        label="Offline Access",
        description="Issue refresh tokens for continued access without re-authorization",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="read:me",
        label="User Profile",
        description="View your Atlassian account profile for account identification",
        access_type="read",
        required=True,
    ),
]

BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create an Atlassian OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically.
    """
    defaults = {"audience": "api.atlassian.com", "prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://auth.atlassian.com/authorize",
        token_url="https://auth.atlassian.com/oauth/token",
        revocation_url="https://auth.atlassian.com/oauth/revoke",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=defaults,
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, StandardRevocationHandler()
