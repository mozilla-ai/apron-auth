"""Microsoft OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Microsoft does not expose a token
revocation endpoint usable by the application's own OAuth scopes —
removing the user's grant requires the user (or a tenant admin) to
remove the application from
``account.live.com/consent/Manage`` or the equivalent enterprise
admin surface. Consumers must surface a deep link to that page.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import SecretStr

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityMaterial, IdentityProfile, ProviderConfig, ScopeMetadata, TenancyContext
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


logger = logging.getLogger(__name__)

# The well-known tenant GUID Microsoft uses for personal MSA accounts.
# Per Microsoft Identity Platform docs: a ``tid`` of this value means the
# user signed in with a Microsoft account (Outlook.com, Xbox, etc.) that
# has no organization tenant. Such a sign-in carries no workforce
# tenancy, so it is treated as ``tenancies=()``.
_MICROSOFT_CONSUMERS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
_MICROSOFT_IDENTITY_HOST_SUFFIXES = ("login.microsoftonline.com",)
_MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"
_MICROSOFT_ORGANIZATION_URL = "https://graph.microsoft.com/v1.0/organization"

# The v2.0 issuer for the commercial cloud. ``{tid}`` is the tenant GUID;
# binding ``iss`` to ``tid`` this way is the chain of trust that promotes
# a bare ``tid`` claim into a validated tenant boundary. Sovereign clouds
# (US Gov, China) use different issuer hosts and are not covered here.
_MICROSOFT_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tid}/v2.0"

# Canonical 8-4-4-4-12 hex GUID. Entra tenant ids are GUIDs; validating
# the shape rejects a non-GUID ``tid`` before it is interpolated into the
# expected issuer.
_GUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def _decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode a JWT payload into a claims dict without verifying its signature.

    NOTE: callers must only pass a token received directly from the
    provider's token endpoint over the back-channel, where the TLS
    transport authenticates the issuer — signature verification is then
    unnecessary, but validating the claims remains the caller's job.

    Returns ``None`` when the token is not a parseable JWT or its payload
    is not a JSON object; the input length is re-padded before decoding
    because JWT segments are unpadded base64url.
    """
    parts = token.split(".")
    if len(parts) < 2:
        logger.debug("microsoft id token is not in JWT shape; skipping claim extraction")
        return None
    try:
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload = json.loads(payload_bytes)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        # Surface a debug signal so operators can detect a future token-
        # format change rather than every workforce sign-in silently
        # degrading to ``tenancies=()``. The exception class is logged,
        # never its value, so no token-derived bytes are emitted.
        logger.debug("microsoft id token claim extraction failed: %s", type(exc).__name__)
        return None
    if not isinstance(payload, dict):
        logger.debug("microsoft id token payload was not a JSON object")
        return None
    return payload


def _verified_workforce_tenant_id(claims: dict[str, Any]) -> str | None:
    """Return the validated workforce tenant GUID from ID-token claims, or ``None``.

    ``None`` means "no workforce tenancy to assert" and is returned when
    any chain-of-trust check fails: ``tid`` is not a GUID, the tenant is
    the personal-account (consumers) tenant, ``iss`` does not match
    ``https://login.microsoftonline.com/{tid}/v2.0``, or the user is a
    B2B guest rather than a member.

    A guest signs in with the host tenant's ``tid`` and therefore passes
    the GUID and issuer checks, but is not a member of it — Microsoft's
    guidance is to treat a guest as a brand-new user, so the tenant's
    verified domains must not be asserted. The ``idp`` claim records the
    authenticating identity provider: it is absent for members (implicitly
    the home tenant) and present and different from ``iss`` for guests.
    """
    tid = claims.get("tid")
    if not isinstance(tid, str) or not _GUID_RE.match(tid):
        return None
    if tid == _MICROSOFT_CONSUMERS_TENANT:
        return None
    if claims.get("iss") != _MICROSOFT_ISSUER_TEMPLATE.format(tid=tid):
        return None
    idp = claims.get("idp")
    if isinstance(idp, str) and idp != claims.get("iss"):
        return None
    return tid


class MicrosoftIdentityHandler:
    """Fetch identity and a verified tenancy for Entra ID workforce sign-in.

    Display fields (``email``, ``name``, ``picture``) come from Microsoft
    Graph's OIDC ``/oidc/userinfo`` endpoint. The trust-bearing claims
    (``sub``, ``tid``, ``iss``, ``idp``) come from the validated ID token
    — never the access token, which Microsoft documents clients should
    not parse. When the ID token establishes a workforce member of a
    real organization tenant, the handler calls Graph
    ``/v1.0/organization`` (readable with the ``User.Read`` scope) and
    emits one :class:`TenancyContext` per admin-verified domain, each
    with ``owns_email_domain=True`` — the Entra analog of Google
    Workspace's ``hd`` claim.

    When no ID token is present, or it does not establish a workforce
    member (personal account, B2B guest, or a failed chain-of-trust
    check), identity is still returned but with ``tenancies=()``: the
    access-token ``tid`` is deliberately not used as a fallback tenancy
    because it is not a validated trust boundary.
    """

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields and any verified tenancy."""
        del config
        payload = await self._fetch_userinfo(material.access_token)

        claims = _decode_jwt_claims(material.id_token) if material.id_token else None
        tenant_id = _verified_workforce_tenant_id(claims) if claims is not None else None

        tenancies: tuple[TenancyContext, ...] = ()
        if tenant_id is not None:
            tenancies = await self._fetch_verified_tenancies(material.access_token, tenant_id)

        return IdentityProfile(
            provider="microsoft",
            subject=_subject(claims, payload),
            email=payload.get("email"),
            email_verified=_email_verified(claims),
            name=payload.get("name"),
            avatar_url=payload.get("picture"),
            tenancies=tenancies,
            raw=payload,
        )

    async def _fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch the OIDC userinfo payload for display fields."""
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
        if not isinstance(payload, dict):
            raise IdentityFetchError("Microsoft identity response was not a JSON object")
        return payload

    async def _fetch_verified_tenancies(self, access_token: str, tenant_id: str) -> tuple[TenancyContext, ...]:
        """Resolve the validated tenant's admin-verified domains into tenancies.

        Emits one :class:`TenancyContext` per verified domain, all sharing
        the validated ``tenant_id`` and the tenant's display name, with
        ``owns_email_domain=True`` because the domains are admin-verified
        and bound to the validated tenant.

        Returns an empty tuple — asserting no domain-owning tenancy — when
        the organization's ``id`` does not match the validated tenant
        (a broken chain of trust) or when it exposes no verified domains.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _MICROSOFT_ORGANIZATION_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            raise IdentityFetchError(f"Failed to fetch Microsoft organization: {exc}") from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse Microsoft organization response: {exc}") from exc

        organizations = body.get("value") if isinstance(body, dict) else None
        organization = organizations[0] if isinstance(organizations, list) and organizations else None
        if not isinstance(organization, dict):
            raise IdentityFetchError("Microsoft organization response contained no organization")

        # Bind the directory response back to the validated ID-token tenant.
        # A mismatch means the access token resolved a different tenant than
        # the one whose chain of trust was validated; refuse to assert
        # ownership rather than trust an unbound directory lookup.
        if organization.get("id") != tenant_id:
            logger.warning(
                "microsoft organization id does not match the validated tenant; not asserting domain ownership"
            )
            return ()

        display_name = organization.get("displayName")
        if not isinstance(display_name, str):
            display_name = None

        verified_domains = organization.get("verifiedDomains")
        if not isinstance(verified_domains, list):
            return ()

        names = [
            entry["name"]
            for entry in verified_domains
            if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"]
        ]
        return tuple(
            TenancyContext(
                id=tenant_id,
                name=display_name,
                domain=name,
                owns_email_domain=True,
            )
            for name in names
        )


def _subject(claims: dict[str, Any] | None, userinfo: dict[str, Any]) -> str | None:
    """Return the user subject, preferring the validated ID-token ``sub``.

    Falls back to the userinfo ``sub`` so identity is still keyed when no
    ID token is present — identity does not require a verified tenancy.
    """
    if claims is not None:
        sub = claims.get("sub")
        if isinstance(sub, str) and sub:
            return sub
    sub = userinfo.get("sub")
    return sub if isinstance(sub, str) and sub else None


def _email_verified(claims: dict[str, Any] | None) -> bool | None:
    """Return the ID token's ``email_verified`` claim, or ``None`` if absent.

    Entra ID does not emit ``email_verified`` for workforce sign-in by
    default; the flag is honored only when the ID token actually carries
    it rather than being assumed.
    """
    if claims is not None and "email_verified" in claims:
        return bool(claims.get("email_verified"))
    return None


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Microsoft identity handler when config matches Microsoft hosts."""
    if oauth_hosts_match(config, _MICROSOFT_IDENTITY_HOST_SUFFIXES):
        return MicrosoftIdentityHandler()
    return None


IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="microsoft",
    resolver=maybe_identity_handler,
)


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
    BASE_SCOPES are merged automatically. ``can_assert_domain_ownership``
    is set: an Entra ID workforce sign-in can carry a verified
    domain-owning tenancy resolved from the ID token and the tenant's
    admin-verified domains.
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
        can_assert_domain_ownership=True,
    )
    return config, None
