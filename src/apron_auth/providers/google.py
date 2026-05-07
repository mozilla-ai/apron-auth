"""Google OAuth provider preset and revocation handler.

``disconnect_fully_revokes=True``: verified per Google's published
OAuth 2.0 documentation. Revoking a token at
``https://oauth2.googleapis.com/revoke`` removes the user's
authorization grant for the client; a subsequent re-auth presents a
fresh consent screen, so the next granted scope set is exactly what
the authorization request asks for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata, TenancyContext
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
_GOOGLE_IDENTITY_HOST_SUFFIXES = ("google.com", "googleapis.com")


class GoogleIdentityHandler:
    """Fetch identity fields from Google's OIDC userinfo endpoint."""

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Google access token."""
        del config
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _GOOGLE_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Google identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Google identity response: {exc}") from exc
        email_verified = None
        if "email_verified" in payload:
            email_verified = bool(payload.get("email_verified"))

        # Google Workspace accounts return the workspace domain via the
        # ``hd`` (hosted domain) claim; consumer (@gmail.com) accounts
        # do not — those legitimately have no tenancy.
        #
        # ``TenancyContext.id`` is intentionally ``None`` for Google:
        # the OIDC userinfo endpoint exposes no Workspace customer ID,
        # which requires the Admin SDK Directory API and admin-only
        # scopes (``admin.directory.customer.readonly``) that consumer
        # apps cannot request. ``hd`` is not repurposed as a synthetic
        # ``id`` because that would conflate "domain" and "tenant
        # identifier" semantically — they coincide for Google but not
        # for providers like Atlassian.
        #
        # ``TenancyContext.name`` is intentionally ``None``: there is
        # no human-readable Workspace display name on the OIDC
        # userinfo response (again, Admin SDK only).
        hd = payload.get("hd")
        tenancies: tuple[TenancyContext, ...] = ()
        if hd:
            tenancies = (TenancyContext(domain=hd),)

        return IdentityProfile(
            subject=payload.get("sub"),
            email=payload.get("email"),
            email_verified=email_verified,
            name=payload.get("name"),
            avatar_url=payload.get("picture"),
            tenancies=tenancies,
            raw=payload,
        )


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


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Google identity handler when config matches Google hosts."""
    if oauth_hosts_match(config, _GOOGLE_IDENTITY_HOST_SUFFIXES):
        return GoogleIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="google",
    resolver=maybe_identity_handler,
)


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="openid",
        label="OpenID",
        description="Authenticate your Google identity",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="https://www.googleapis.com/auth/userinfo.email",
        label="Email Address",
        description="View your email address for account identification",
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
    """Create a Google OAuth provider configuration.

    Default extra_params include access_type=offline and prompt=consent
    for offline access. Scopes from BASE_SCOPES are merged automatically.
    """
    defaults = {"access_type": "offline", "prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        revocation_url="https://oauth2.googleapis.com/revoke",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=defaults,
        disconnect_fully_revokes=True,
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, GoogleRevocationHandler()
