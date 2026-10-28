"""Google OAuth provider preset and revocation handler.

``disconnect_fully_revokes=True``: verified per Google's published
OAuth 2.0 documentation. Revoking a token at
``https://oauth2.googleapis.com/revoke`` removes the user's
authorization grant for the client; a subsequent re-auth presents a
fresh consent screen, so the next granted scope set is exactly what
the authorization request asks for.
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from apron_auth.models import IdentityMaterial, IdentityProfile, Provider, ProviderConfig, ScopeMetadata, TenancyContext
from apron_auth.protocols import TransportFactory
from apron_auth.providers._identity_requests import fetch_identity_json
from apron_auth.providers._presets import Preset
from apron_auth.providers._revocation import RevocationRequest, revocation_endpoint, send_revocation

# The scopes the preset always requests, with the labels a consent screen shows.
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

# The scope strings that the preset adds to the caller's scopes.
BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]

# What this provider's preset states, beside the values its caller passes.
_PRESET = Preset(
    provider=Provider.GOOGLE,
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    revocation_url="https://oauth2.googleapis.com/revoke",
    base_scopes=BASE_SCOPES,
    default_extra_params={"access_type": "offline", "prompt": "consent"},
    scope_metadata=BASE_SCOPE_METADATA,
)

# The endpoint that returns the signed-in user's profile.
_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class GoogleIdentityHandler:
    """Fetch identity fields from Google's OIDC userinfo endpoint."""

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Google access token.

        Args:
            material: The token material to establish identity from.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile. A Workspace ``hd`` claim, when present,
            is surfaced as a domain-owning tenancy.

        Raises:
            IdentityFetchError: If the userinfo request fails or its
                response cannot be parsed.
                The failed request's error is not attached as its cause or context.
        """
        del config
        async with httpx.AsyncClient() as client:
            payload = await fetch_identity_json(
                client.get(
                    _GOOGLE_USERINFO_URL,
                    headers={"Authorization": f"Bearer {material.access_token}"},
                ),
                "Google identity",
            )
        # Honor email_verified only as a genuine boolean; a bare bool()
        # would coerce a non-boolean (e.g. the string "false") to True.
        email_verified = payload.get("email_verified")
        if not isinstance(email_verified, bool):
            email_verified = None

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
            tenancies = (TenancyContext(domain=hd, owns_email_domain=True),)

        return IdentityProfile(
            provider=Provider.GOOGLE,
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

    def __init__(self, *, transport_factory: TransportFactory | None = None) -> None:
        """Configure how revocation requests reach the network.

        Args:
            transport_factory: Controls the outbound connection for the revocation URL. The URL is
                server-supplied, so a caller handling untrusted input can pin DNS to validated
                addresses here to prevent SSRF via rebinding.
        """
        self._transport_factory = transport_factory

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token at Google's revocation endpoint.

        Args:
            token: The token to revoke.
            config: The provider configuration supplying the revocation URL.

        Returns:
            ``True`` when the endpoint reports success.

        Raises:
            ConfigurationError: If ``config`` has no revocation URL.
            RevocationError: If the request cannot be sent or fails to arrive.
                The failed request's error is not attached as its cause or context.
        """
        request = RevocationRequest(
            url=revocation_endpoint(config),
            label="Google",
            params={"token": token},
        )
        response = await send_revocation(request, transport_factory=self._transport_factory)
        return response.is_success


def preset(
    client_id: str,
    client_secret: str,
    *,
    scopes: Sequence[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> ProviderConfig:
    """Create a Google OAuth provider configuration.

    Default extra_params include access_type=offline and prompt=consent
    for offline access. Scopes from BASE_SCOPES are merged automatically.

    Args:
        client_id: The OAuth client identifier.
        client_secret: The OAuth client secret.
        scopes: Additional scopes to request; merged with the required
            base scopes.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters; merged over
            the ``access_type=offline`` and ``prompt=consent`` defaults.

    Returns:
        The provider configuration. The client resolves this provider's revocation handler
        from it.
    """
    return _PRESET.config(client_id, client_secret, scopes=scopes, redirect_uri=redirect_uri, extra_params=extra_params)
