"""Typeform OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Typeform does not expose an OAuth
revocation endpoint at all (no revocation handler is returned), so
apron-auth has no way to remove the portal-level grant.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_TYPEFORM_USERINFO_URL = "https://api.typeform.com/me"
_TYPEFORM_IDENTITY_HOST_SUFFIXES = ("api.typeform.com",)


class TypeformIdentityHandler:
    """Fetch identity fields from Typeform's ``/me`` endpoint.

    Requires the ``accounts:read`` OAuth scope. The Typeform response
    documents only ``alias``, ``email``, and ``language``, so
    ``IdentityProfile.subject`` is always ``None`` for this provider —
    Typeform does not expose a stable, opaque user identifier. The
    available alternatives are ``email`` (stable but PII) and
    ``username`` (the Typeform ``alias``, which is user-mutable);
    callers that need a non-PII stable handle must derive one
    themselves, for example by hashing ``email``.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Typeform access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _TYPEFORM_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Typeform identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Typeform identity response: {exc}") from exc

        # Typeform "workspaces" are intra-account containers, not
        # OAuth-scoping contexts. A token authenticates the user and
        # grants access — governed by ``workspaces:read`` /
        # ``workspaces:write`` scopes — across every workspace the
        # user can see, so there is no normalized tenancy to populate.
        return IdentityProfile(
            subject=None,
            email=payload.get("email"),
            email_verified=None,
            name=None,
            username=payload.get("alias"),
            avatar_url=None,
            tenancies=(),
            raw=payload,
        )


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Typeform identity handler when config matches Typeform hosts."""
    if oauth_hosts_match(config, _TYPEFORM_IDENTITY_HOST_SUFFIXES):
        return TypeformIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="typeform",
    resolver=maybe_identity_handler,
)


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a Typeform OAuth provider configuration.

    Typeform does not support PKCE and does not provide a revocation
    endpoint.
    """
    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://api.typeform.com/oauth/authorize",
        token_url="https://api.typeform.com/oauth/token",
        redirect_uri=redirect_uri,
        scopes=scopes,
        use_pkce=False,
        extra_params=extra_params or {},
    )
    return config, None
