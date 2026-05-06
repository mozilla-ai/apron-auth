"""Salesforce OAuth provider preset and identity handler.

``disconnect_fully_revokes`` defaults to ``False``: Salesforce's
RFC 7009 ``/services/oauth2/revoke`` invalidates the supplied token
but its effect on the org-level Connected App authorization has not
been verified end-to-end. Tracking issue: #35.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, ScopeMetadata
from apron_auth.protocols import StandardRevocationHandler

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


_SALESFORCE_USERINFO_PATH = "/services/oauth2/userinfo"
_SALESFORCE_IDENTITY_HOST_SUFFIXES = ("salesforce.com",)


class SalesforceIdentityHandler:
    """Fetch identity fields from Salesforce's OIDC userinfo endpoint.

    The userinfo endpoint lives at ``/services/oauth2/userinfo`` on the
    same host used for the OAuth authorize and token endpoints, so the
    URL is derived from ``config.authorize_url`` rather than threaded
    through a separate ``instance_url`` parameter. This keeps the
    ``IdentityHandler`` protocol unchanged and reuses the existing
    Salesforce ``host`` preset override (sandbox, My Domain) without
    further plumbing.

    Requires the ``openid`` OAuth scope; ``profile`` and ``email``
    enrich the response.

    ``IdentityProfile.email_verified`` mirrors Salesforce's
    ``email_verified`` claim, which becomes ``True`` only after the
    user clicks the link in their welcome email (or re-verifies after
    an email/password change or new-device challenge) — it is not a
    general "is this address real" signal.
    """

    async def fetch_identity(self, access_token: str, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields using a Salesforce access token."""
        parsed = urlparse(config.authorize_url)
        if not parsed.hostname:
            msg = f"Salesforce identity fetch requires a hostname in authorize_url; got {config.authorize_url!r}"
            raise IdentityFetchError(msg)
        userinfo_url = f"https://{parsed.hostname}{_SALESFORCE_USERINFO_PATH}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Salesforce identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Salesforce identity response: {exc}") from exc

        email_verified = None
        if "email_verified" in payload:
            email_verified = bool(payload.get("email_verified"))

        username = payload.get("nickname") or payload.get("preferred_username")

        return IdentityProfile(
            subject=payload.get("sub"),
            email=payload.get("email"),
            email_verified=email_verified,
            name=payload.get("name"),
            username=username,
            avatar_url=payload.get("picture"),
            raw=payload,
        )


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Salesforce identity handler when config matches Salesforce hosts."""
    hosts = (config.authorize_url, config.token_url)
    for url in hosts:
        host = urlparse(url).hostname or ""
        if any(host == suffix or host.endswith("." + suffix) for suffix in _SALESFORCE_IDENTITY_HOST_SUFFIXES):
            return SalesforceIdentityHandler()
    return None


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="refresh_token",
        label="Refresh Token",
        description="Issue a refresh token so access can be renewed without re-authorization",
        access_type="read",
        required=True,
    ),
    ScopeMetadata(
        scope="offline_access",
        label="Offline Access",
        description="Maintain access to your Salesforce data when you are not actively using the app",
        access_type="read",
        required=True,
    ),
]

BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]

_FORBIDDEN_HOST_CHARS = frozenset("/?#@ \t\n\r")


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
    host: str = "login.salesforce.com",
) -> tuple[ProviderConfig, RevocationHandler]:
    """Create a Salesforce OAuth provider configuration.

    Scopes from BASE_SCOPES are merged automatically — Salesforce
    requires both ``refresh_token`` and ``offline_access`` to issue
    a refresh token at the code-exchange step.

    ``host`` selects the Salesforce login host. Use
    ``test.salesforce.com`` for sandboxes, or a My Domain host (e.g.
    ``acme.my.salesforce.com``) for orgs that require it. It must be a
    bare hostname — no scheme, path, query, or whitespace — and is
    rejected with :class:`ValueError` otherwise so misconfiguration
    fails fast rather than producing a malformed OAuth endpoint.
    """
    if not host or any(c in _FORBIDDEN_HOST_CHARS for c in host):
        msg = f"host must be a bare hostname like 'login.salesforce.com' (no scheme, path, or whitespace); got {host!r}"
        raise ValueError(msg)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url=f"https://{host}/services/oauth2/authorize",
        token_url=f"https://{host}/services/oauth2/token",
        revocation_url=f"https://{host}/services/oauth2/revoke",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        extra_params=extra_params or {},
        scope_metadata=BASE_SCOPE_METADATA,
    )
    return config, StandardRevocationHandler()
