"""Microsoft OAuth provider preset and identity handler.

``disconnect_fully_revokes=False``: Microsoft does not expose a token
revocation endpoint usable by the application's own OAuth scopes —
removing the user's grant requires the user (or a tenant admin) to
remove the application from
``account.live.com/consent/Manage`` or the equivalent enterprise
admin surface. Consumers must surface a deep link to that page.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx
from joserfc.errors import ClaimError, ExpiredTokenError, JoseError, MissingClaimError
from joserfc.jwt import JWTClaimsRegistry
from pydantic import SecretStr

from apron_auth._http_errors import http_failure
from apron_auth._json_body import decode_json_body
from apron_auth._jwt import CLOCK_SKEW_SECONDS, claim_refusal_reason
from apron_auth.errors import (
    FailureKind,
    IdentityFetchError,
    TokenExpiredError,
    TokenValidationError,
    TokenValidationReason,
)
from apron_auth.models import IdentityMaterial, IdentityProfile, Provider, ProviderConfig, ScopeMetadata, TenancyContext
from apron_auth.providers._host_match import oauth_hosts_match
from apron_auth.providers._identity_registry import IdentityResolverRegistration
from apron_auth.providers._identity_requests import fetch_identity_json
from apron_auth.providers._jwks import IssuerSigningKeys, SigningAlgorithm

if TYPE_CHECKING:
    from apron_auth.protocols import IdentityHandler, RevocationHandler


logger = logging.getLogger(__name__)

# The scopes the preset always requests, with the labels a consent screen shows.
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

# The scope strings that the preset adds to the caller's scopes.
BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]

# Canonical 8-4-4-4-12 hex GUID. Entra tenant IDs are GUIDs; validating
# the shape rejects a non-GUID ``tid`` before it is interpolated into the
# expected issuer.
_GUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")

# The well-known tenant GUID Microsoft uses for personal MSA accounts.
# Per Microsoft Identity Platform docs: a ``tid`` of this value means the
# user signed in with a Microsoft account (Outlook.com, Xbox, etc.) that
# has no organization tenant. Such a sign-in carries no workforce
# tenancy, so it is treated as ``tenancies=()``.
_MICROSOFT_CONSUMERS_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"

# The v2.0 issuer for the commercial cloud. ``{tid}`` is the tenant GUID;
# binding ``iss`` to ``tid`` this way is the chain of trust that promotes
# a bare ``tid`` claim into a validated tenant boundary. Sovereign clouds
# (US Gov, China) use different issuer hosts and are not covered here.
_MICROSOFT_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tid}/v2.0"

# One key set signs ID tokens for every tenant and personal accounts, except apps with custom signing keys.
# It is pinned rather than discovered, so no metadata document can point verification at other keys.
_MICROSOFT_KEYS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

# The Microsoft Graph endpoint that returns the tenant's organization, with its verified domains.
_MICROSOFT_ORGANIZATION_URL = "https://graph.microsoft.com/v1.0/organization"

# The OpenID userinfo endpoint of Microsoft Graph.
_MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/oidc/userinfo"


class _IdToken(NamedTuple):
    """The fields of a Microsoft ID token whose signature and claims checked out."""

    claims: dict[str, Any]
    issuer: str
    subject: str
    tenant_id: str


def _verified_workforce_tenant_id(id_token: _IdToken) -> str | None:
    """Return the workforce tenant GUID of a validated ID token, or ``None``.

    ``None`` means there is no workforce tenancy to assert: the tenant is the personal-account (consumers) tenant,
    or the user is a B2B guest rather than a member.

    A guest signs in with the host tenant's ``tid`` but is not a member of it.
    Microsoft's guidance is to treat a guest as a new user, so the tenant's verified domains must not be asserted.
    The ``idp`` claim names the authenticating identity provider.
    It is absent for members, so any ``idp`` that is present and is not exactly ``iss`` marks a guest.

    Args:
        id_token: The validated ID token.

    Returns:
        The workforce tenant GUID, or ``None`` when no workforce tenancy can be asserted.
    """
    if id_token.tenant_id == _MICROSOFT_CONSUMERS_TENANT:
        return None
    if "idp" in id_token.claims and id_token.claims["idp"] != id_token.issuer:
        return None
    return id_token.tenant_id


def _checked_id_token(claims: dict[str, Any], client_id: str, key_issuer: object) -> _IdToken:
    """Validate a signature-checked Microsoft ID token's claims.

    ``iss`` must name the token's own tenant, and so must the signing key when it names an issuer.
    ``aud`` must be the client identifier alone, because Microsoft issues ID tokens with a single audience.
    Entra application IDs are GUIDs, so they match regardless of letter case.

    Args:
        claims: The claims of an ID token whose signature verified.
        client_id: The client identifier the token's ``aud`` must name.
        key_issuer: The ``issuer`` the verifying key was published with, or ``None`` when it names none.

    Returns:
        The validated ID token.

    Raises:
        TokenExpiredError: If the token has expired.
        TokenValidationError: If any other claim does not validate.
    """
    tid = claims.get("tid")
    if not isinstance(tid, str) or not _GUID_RE.match(tid):
        msg = "Microsoft ID token has an invalid tid claim"
        raise TokenValidationError(msg, reason=TokenValidationReason.CLAIMS)
    issuer = _MICROSOFT_ISSUER_TEMPLATE.format(tid=tid)
    if claims.get("iss") != issuer:
        msg = "Microsoft ID token has an invalid iss claim"
        raise TokenValidationError(msg, reason=TokenValidationReason.UNKNOWN_ISSUER)
    # The key set lists each key's issuer with a tenant placeholder, so one key cannot vouch for another issuer.
    if key_issuer is not None and (not isinstance(key_issuer, str) or key_issuer.replace("{tenantid}", tid) != issuer):
        msg = "Microsoft ID token signing key belongs to another issuer"
        raise TokenValidationError(msg, reason=TokenValidationReason.UNKNOWN_ISSUER)
    if not _same_client(claims.get("aud"), client_id):
        msg = "Microsoft ID token has an invalid aud claim"
        raise TokenValidationError(msg, reason=TokenValidationReason.AUDIENCE)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        msg = "Microsoft ID token has an invalid sub claim"
        raise TokenValidationError(msg, reason=TokenValidationReason.CLAIMS)
    lifetime = JWTClaimsRegistry(leeway=CLOCK_SKEW_SECONDS, exp={"essential": True}, iat={"essential": True})
    try:
        lifetime.validate(claims)
    except ExpiredTokenError as exc:
        raise TokenExpiredError("Microsoft ID token has expired") from exc
    except MissingClaimError as exc:
        # The library joins several missing claim names with commas.
        missing = ", ".join(exc.claim.split(","))
        noun = "claims" if "," in exc.claim else "claim"
        raise TokenValidationError(
            f"Microsoft ID token is missing the {missing} {noun}", reason=TokenValidationReason.CLAIMS
        ) from exc
    except ClaimError as exc:
        raise TokenValidationError(
            f"Microsoft ID token has an invalid {exc.claim} claim", reason=claim_refusal_reason(exc.claim)
        ) from exc
    except (JoseError, TypeError, ValueError) as exc:
        # A claim of the wrong JSON type can raise outside the library's own errors.
        raise TokenValidationError(
            "Microsoft ID token claims did not validate", reason=TokenValidationReason.CLAIMS
        ) from exc
    return _IdToken(claims=claims, issuer=issuer, subject=subject, tenant_id=tid)


def _same_client(audience: object, client_id: str) -> bool:
    """Return whether an ID token's ``aud`` names ``client_id``, ignoring case when both are GUIDs.

    Args:
        audience: The token's ``aud`` claim.
        client_id: The configured client identifier.

    Returns:
        Whether the audience is that one client.
    """
    if not isinstance(audience, str):
        return False
    if _GUID_RE.match(audience) and _GUID_RE.match(client_id):
        return audience.lower() == client_id.lower()
    return audience == client_id


class MicrosoftIdentityHandler:
    """Fetch identity and a verified tenancy for Entra ID workforce sign-in.

    Display fields (``email``, ``name``, ``picture``) come from Microsoft Graph's OIDC ``/oidc/userinfo`` endpoint.
    The trust-bearing claims (``sub``, ``tid``, ``iss``, ``idp``) come from the ID token,
    never the access token, which Microsoft documents clients should not parse.

    The ID token's signature is checked against Microsoft's published keys before any claim is used.
    Its ``iss`` must name the token's own tenant, and its ``aud``, ``exp``, ``iat``, ``nbf`` and ``sub`` are validated.
    A token that does not validate raises before any Graph request.
    A userinfo response whose ``sub`` is missing or differs from the ID token's is refused.
    The handler caches Microsoft's keys, so one handler serves every sign-in.
    Only the v2.0 endpoints are supported, and an app that uses custom signing keys from claims mapping is not.

    When the ID token establishes a workforce member of a real organization tenant,
    the handler calls Graph ``/v1.0/organization`` (readable with the ``User.Read`` scope).
    It emits one :class:`TenancyContext` per admin-verified domain, each with ``owns_email_domain=True``,
    the Entra analog of Google Workspace's ``hd`` claim.

    When no ID token is present, or it names a personal account or a B2B guest,
    identity is still returned but with ``tenancies=()``.
    The access-token ``tid`` is never a fallback tenancy, because it is not a validated trust boundary.
    A directory lookup that fails or cannot be trusted degrades the same way, to ``tenancies=()`` and a logged warning.
    """

    def __init__(self) -> None:
        """Prepare the cache of Microsoft's ID token signing keys."""
        # Microsoft signs ID tokens with RS256 only.
        self._signing_keys = IssuerSigningKeys(_MICROSOFT_KEYS_URL, algorithms=(SigningAlgorithm.RS256,))

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields and any verified tenancy.

        Args:
            material: The token material: the access token and, when present, the ID token.
            config: The provider configuration the tokens were issued under.

        Returns:
            The identity profile.
            A workforce sign-in contributes one domain-owning tenancy per admin-verified domain,
            and every other case yields ``tenancies=()``.

        Raises:
            TokenExpiredError: If the ID token verifies but has expired.
            TokenValidationError: If the ID token's signature or claims do not validate.
            IdentityFetchError: If Microsoft's signing keys cannot be fetched.
                It is also raised if the userinfo request fails, its response cannot be parsed,
                or it names no subject or a different one than the ID token.
                Directory lookups never raise, and degrade to no tenancy instead.
        """
        id_token = None
        if material.id_token:
            verified = await self._signing_keys.verify(material.id_token)
            id_token = _checked_id_token(verified.claims, config.client_id, verified.key.get("issuer"))
        payload = await self._fetch_userinfo(material.access_token)
        if id_token is not None:
            _require_matching_subject(id_token, payload)

        tenant_id = _verified_workforce_tenant_id(id_token) if id_token is not None else None

        tenancies: tuple[TenancyContext, ...] = ()
        if tenant_id is not None:
            tenancies = await self._fetch_verified_tenancies(material.access_token, tenant_id)

        email = payload.get("email")
        return IdentityProfile(
            provider=Provider.MICROSOFT,
            subject=id_token.subject if id_token is not None else _userinfo_subject(payload),
            email=email,
            email_verified=_email_verified(id_token, email),
            name=payload.get("name"),
            avatar_url=payload.get("picture"),
            tenancies=tenancies,
            raw=payload,
        )

    async def _fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch the OIDC userinfo payload for display fields.

        Args:
            access_token: The bearer access token for the userinfo request.

        Returns:
            The userinfo payload as a JSON object.

        Raises:
            IdentityFetchError: If the request fails, its response cannot be
                parsed, or it is not a JSON object.
                The failed request's error is not attached as its cause or context.
        """
        async with httpx.AsyncClient() as client:
            payload = await fetch_identity_json(
                client.get(
                    _MICROSOFT_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                ),
                "Microsoft identity",
            )
        if not isinstance(payload, dict):
            msg = "Microsoft identity response was not a JSON object"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED)
        return payload

    async def _fetch_organization(self, access_token: str) -> dict[str, Any] | None:
        """Fetch the signed-in user's organization from the directory, or ``None``.

        ``None`` means the directory yielded no usable organization: it
        was unreachable, refused the request, or returned a body that was
        unparseable or named no organization. Each case is logged.

        NOTE: this never raises. The organization only enriches an
        already-established identity, so its absence must be reported as
        a value rather than escalated into an error.

        Args:
            access_token: The bearer access token for the directory request.

        Returns:
            The signed-in user's organization, or ``None`` when the
            directory yields no usable organization.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    _MICROSOFT_ORGANIZATION_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # The status is the whole diagnostic here — it separates a
            # permanent consent or permission problem from a transient
            # one. The exception value adds only the request line.
            logger.warning(
                "microsoft directory lookup could not resolve the tenant's verified domains "
                "(status %s); not asserting domain ownership",
                exc.response.status_code,
            )
            return None
        except httpx.RequestError as exc:
            logger.warning(
                "microsoft directory lookup could not resolve the tenant's verified domains "
                "(%s); not asserting domain ownership",
                http_failure(exc).description,
            )
            return None

        try:
            body = decode_json_body(response)
        except ValueError:
            logger.warning(
                "microsoft directory lookup could not parse the tenant's verified domains; "
                "not asserting domain ownership"
            )
            return None

        organizations = body.get("value") if isinstance(body, dict) else None
        organization = organizations[0] if isinstance(organizations, list) and organizations else None
        if not isinstance(organization, dict):
            logger.warning("microsoft directory lookup returned no organization; not asserting domain ownership")
            return None
        return organization

    async def _fetch_verified_tenancies(self, access_token: str, tenant_id: str) -> tuple[TenancyContext, ...]:
        """Resolve the validated tenant's admin-verified domains into tenancies.

        Emits one :class:`TenancyContext` per verified domain, all sharing
        the validated ``tenant_id`` and the tenant's display name, with
        ``owns_email_domain=True`` because the domains are admin-verified
        and bound to the validated tenant.

        Returns an empty tuple — asserting no domain-owning tenancy — for
        every failure to establish one: the directory yields no usable
        organization, the organization's ``id`` does not match the
        validated tenant (a broken chain of trust), or it exposes no
        verified domains.

        NOTE: this never raises. Withholding the assertion closes
        domain-gated access rather than opening it, so a directory
        failure must not be escalated into a failure to identify.

        Args:
            access_token: The bearer access token for the directory request.
            tenant_id: The validated ID-token tenant GUID the directory
                response must bind back to.

        Returns:
            One domain-owning tenancy per admin-verified domain, or an empty
            tuple when no such tenancy can be established.
        """
        organization = await self._fetch_organization(access_token)
        if organization is None:
            return ()

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
        names = (
            [
                entry["name"]
                for entry in verified_domains
                if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"]
            ]
            if isinstance(verified_domains, list)
            else []
        )
        if not names:
            # Every Entra tenant has at least an ``*.onmicrosoft.com``
            # domain, so an organization naming none is anomalous rather
            # than a tenant legitimately owning nothing.
            logger.warning("microsoft organization exposed no usable verified domains; not asserting domain ownership")
            return ()

        return tuple(
            TenancyContext(
                id=tenant_id,
                name=display_name,
                domain=name,
                owns_email_domain=True,
            )
            for name in names
        )


def _require_matching_subject(id_token: _IdToken, userinfo: dict[str, Any]) -> None:
    """Refuse a userinfo response that does not name the ID token's subject.

    OpenID Connect Core 1.0 section 5.3.2 requires the two to match, so a mismatch is refused, not reconciled.

    Args:
        id_token: The validated ID token.
        userinfo: The OIDC userinfo payload.

    Raises:
        IdentityFetchError: If userinfo names no subject or a different one.
    """
    userinfo_subject = userinfo.get("sub")
    if not isinstance(userinfo_subject, str) or not userinfo_subject:
        msg = "Microsoft userinfo response names no subject to match the ID token's"
        raise IdentityFetchError(msg, kind=FailureKind.REFUSED)
    if userinfo_subject != id_token.subject:
        msg = "Microsoft userinfo response names a different subject than the ID token"
        raise IdentityFetchError(msg, kind=FailureKind.REFUSED)


def _userinfo_subject(userinfo: dict[str, Any]) -> str | None:
    """Return the userinfo ``sub``, which keys identity when there is no ID token.

    Args:
        userinfo: The OIDC userinfo payload.

    Returns:
        The subject, or ``None`` when userinfo names none.
    """
    sub = userinfo.get("sub")
    return sub if isinstance(sub, str) and sub else None


def _email_verified(id_token: _IdToken | None, email: object) -> bool | None:
    """Return the ID token's ``email_verified`` for ``email``, or ``None`` when it asserts nothing about it.

    The claim vouches only for the ID token's own ``email``, so it counts only when that equals the reported email.
    The comparison is exact, because a case-folded match would extend the assertion to an address the token never named.
    Entra ID does not emit ``email_verified`` for workforce sign-in by default.
    A non-boolean value is reported as unknown rather than coerced, because ``bool("false")`` is ``True``.

    Args:
        id_token: The validated ID token, or ``None`` when absent.
        email: The email the profile reports, from userinfo.

    Returns:
        The claim when it is a genuine boolean asserted for ``email``, else ``None``.
    """
    if id_token is None or not isinstance(email, str) or id_token.claims.get("email") != email:
        return None
    value = id_token.claims.get("email_verified")
    return value if isinstance(value, bool) else None


def maybe_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Return the Microsoft identity handler when config matches Microsoft hosts.

    Args:
        config: The provider configuration to match.

    Returns:
        A Microsoft identity handler when the config's OAuth hosts are
        Microsoft's, else ``None``.
    """
    if oauth_hosts_match(config, Provider.MICROSOFT.host_suffixes):
        return MicrosoftIdentityHandler()
    return None


# The entry that lets the client infer this provider's identity handler.
IDENTITY_RESOLVER = IdentityResolverRegistration(
    provider="microsoft",
    resolver=maybe_identity_handler,
)


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

    Args:
        client_id: The OAuth client identifier. A GUID is stored in lowercase, which names the same
            application and is how Entra names it in an ID token's audience.
        client_secret: The OAuth client secret.
        scopes: Additional scopes to request; merged with the required
            base scopes.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters; merged over
            the ``prompt=consent`` default.

    Returns:
        The provider configuration paired with ``None``, as Microsoft
        exposes no revocation endpoint.
    """
    defaults = {"prompt": "consent"}
    if extra_params:
        defaults.update(extra_params)

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))

    # Entra names the client in an ID token's audience by its lowercase GUID, and a GUID is case-insensitive.
    if _GUID_RE.match(client_id):
        client_id = client_id.lower()

    config = ProviderConfig(
        provider=Provider.MICROSOFT,
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        scope_separator=Provider.MICROSOFT.scope_separator,
        disconnect_fully_revokes=Provider.MICROSOFT.disconnect_fully_revokes,
        extra_params=defaults,
        scope_metadata=BASE_SCOPE_METADATA,
        can_assert_domain_ownership=True,
    )
    return config, None
