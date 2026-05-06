"""Microsoft OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Microsoft does not expose a token
revocation endpoint usable by the application's own OAuth scopes —
removing the user's grant requires the user (or a tenant admin) to
remove the application from
``account.live.com/consent/Manage`` or the equivalent enterprise
admin surface. Consumers must surface a deep link to that page.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"
_MICROSOFT_IDENTITY_HOST_SUFFIXES = ("login.microsoftonline.com",)


class MicrosoftIdentityHandler:
    """Fetch identity fields from Microsoft Graph's OIDC userinfo endpoint."""

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Microsoft access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _MICROSOFT_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Microsoft identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Microsoft identity response: {exc}") from exc

        return IdentityProfile(
            subject=payload.get("sub"),
            email=payload.get("email"),
            email_verified=None,
            name=payload.get("name"),
            avatar_url=payload.get("picture"),
            raw=payload,
        )


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Microsoft identity handler when config matches Microsoft hosts."""
    if oauth_hosts_match(config, _MICROSOFT_IDENTITY_HOST_SUFFIXES):
        return MicrosoftIdentityHandler()
    return None


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="offline_access",
        label="Offline Access",
        description="Maintain access to data you have given it access to",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="openid",
        label="OpenID",
        description="Sign you in",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="User.Read",
        label="User Profile",
        description="Sign you in and read your profile",
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
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a Microsoft OAuth provider configuration.

    Microsoft does not provide a token revocation endpoint. Scopes from
    BASE_SCOPES are merged automatically.
    """
    defaults = {"prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=defaults,
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, None
