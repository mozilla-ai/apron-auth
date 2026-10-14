"""Generic OpenID Connect provider preset, discovery, and identity handler.

An OpenID provider publishes its own configuration document.
:func:`discover` reads the endpoints from the issuer, and :func:`preset` combines them with a client identity.
This covers Keycloak, Okta, Auth0, Entra ID, Authentik, Zitadel, Dex, Ping,
and any other provider that implements OpenID Connect Discovery 1.0.

Always pass :func:`identity_handler` to :class:`~apron_auth.client.OAuthClient`.
On a host that a built-in provider also serves,
an inferred handler would change ``provider`` and every user's ``identity_key()``.
A config from :func:`preset` therefore disallows handler inference.
Without a handler, ``OAuthClient.fetch_identity`` raises :class:`~apron_auth.errors.IdentityNotSupportedError`.

ID token signatures are not verified.
Tokens arrive on the token-endpoint response, where TLS authenticates the issuer.
OpenID Connect Core 1.0 section 3.1.3.7 allows this.
Claims are always validated per that section.
Every URL here must be ``https``, because the design relies on TLS.
Pass the handler only tokens from a token-endpoint response.

Limitations
-----------

* Confidential clients only.
  :func:`preset` requires a client secret.
* No ``nonce`` and no per-request authorization parameters.
  PKCE is the only code-injection defense, and it holds only where the provider enforces it.
* No RP-Initiated Logout and no ``response_mode``.
  The query default is used.
* A token response without an ``id_token`` is accepted.
  Identity then falls back to userinfo alone, which has a weaker claim to have vouched for it.
* A signed (``application/jwt``) userinfo response is refused.
* ``https`` is required for the issuer, the document URL and every endpoint.
  :func:`discover`, :func:`preset` and :func:`identity_handler` take ``allow_insecure_http``
  for local development.
"""

from __future__ import annotations

import json
import logging
import re
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
from authlib.oidc.core import CodeIDToken
from authlib.oidc.discovery import get_well_known_url
from joserfc import jws
from joserfc.errors import ClaimError, JoseError
from pydantic import SecretStr

from apron_auth._discovery import CONFIDENTIAL_AUTH_METHODS, discovery_client, str_list
from apron_auth.errors import (
    ConfigurationError,
    IdentityFetchError,
    IdentityScopeNotGrantedError,
    OidcDiscoveryError,
)
from apron_auth.models import (
    IdentityMaterial,
    IdentityProfile,
    ProviderConfig,
    ScopeMetadata,
    ServerMetadata,
    TokenEndpointAuthMethod,
)
from apron_auth.protocols import StandardRevocationHandler
from apron_auth.providers._http_errors import describe_http_error

if TYPE_CHECKING:
    from collections.abc import Sequence

    from apron_auth.protocols import RevocationHandler, TransportFactory


logger = logging.getLogger(__name__)

_USERINFO_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Clock skew allowed on ``exp``, ``iat`` and ``nbf``.
_CLOCK_SKEW_SECONDS = 60


BASE_SCOPE_METADATA = [
    ScopeMetadata(
        scope="openid",
        label="OpenID",
        description="Sign you in and confirm your identity",
        access_type="read",
        required=True,
    ),
]

BASE_SCOPES = [meta.scope for meta in BASE_SCOPE_METADATA]


def discovery_url(issuer: str, *, allow_insecure_http: bool = False) -> str:
    """The document URL for ``issuer``, per OpenID Connect Discovery 1.0 section 4.

    The well-known suffix is appended to the issuer including its path, and a trailing slash does not double up.
    A realm at ``https://sso.example.com/realms/acme`` therefore publishes under that path, not at the host root.
    The issuer must be an absolute URL with no query, fragment or userinfo.
    It must use ``https`` unless ``allow_insecure_http`` is set.

    Args:
        issuer: The issuer identifier to derive the document URL from.
        allow_insecure_http: Accept an ``http`` issuer, for local development.

    Returns:
        The configuration document's URL.

    Raises:
        OidcDiscoveryError: If ``issuer`` is not a parseable absolute URL or has a query, fragment or userinfo.
            It is also raised if ``issuer`` is not ``https`` and ``allow_insecure_http`` is unset.
    """
    _require_url(issuer, field="issuer", allow_insecure_http=allow_insecure_http, is_issuer=True)
    return get_well_known_url(issuer, external=True)


async def discover(
    issuer: str,
    *,
    document_url: str | None = None,
    transport_factory: TransportFactory | None = None,
    allow_insecure_http: bool = False,
) -> ServerMetadata:
    """Read an OpenID provider's configuration document.

    A document that names an issuer other than ``issuer`` is refused (OpenID Connect Discovery 1.0, section 4.3).
    Every later ``iss`` check therefore compares against an issuer the caller chose.

    Args:
        issuer: The issuer identifier, which the document must also name.
            It is the value an operator configures, and an authorization response's ``iss`` is checked against it.
        document_url: Where to fetch the document, when it is not at the standard suffix.
            The issuer check still applies, so an override moves the document without loosening what it may claim.
        transport_factory: Optional factory returning an httpx transport for the document URL.
            Host policy belongs here, because a check on the URL string cannot see where a hostname resolves.
        allow_insecure_http: Accept ``http`` for the issuer, the document URL and the endpoints the document names.
            It is off by default, because ID tokens are not signature-checked and rely on TLS for the issuer.
            Over ``http``, an on-path attacker chooses every claim and reads the client secret.
            It is for local development only, and it logs a WARNING for each URL it lets through.

    Returns:
        The discovered metadata, including the userinfo endpoint.

    Raises:
        OidcDiscoveryError: If the issuer is malformed, or a URL is not ``https`` and ``allow_insecure_http`` is unset.
            It is also raised if the document cannot be fetched or parsed, omits a required endpoint,
            or names an issuer other than ``issuer``.
    """
    url = discovery_url(issuer, allow_insecure_http=allow_insecure_http)
    if document_url is not None:
        _require_url(document_url, field="document URL", allow_insecure_http=allow_insecure_http)
        url = document_url
    document = await _fetch_document(url, transport_factory)

    declared_issuer = document.get("issuer")
    if not isinstance(declared_issuer, str) or not declared_issuer:
        msg = "OpenID provider configuration declares no issuer"
        raise OidcDiscoveryError(msg)
    # Compared exactly: RFC 8414 section 2 allows no trailing slash, and normalizing would hide a mismatch.
    if declared_issuer != issuer:
        msg = "OpenID provider configuration declares a different issuer than the one it was fetched for"
        raise OidcDiscoveryError(msg)

    authorize_url = document.get("authorization_endpoint")
    token_url = document.get("token_endpoint")
    if authorize_url is None or token_url is None:
        msg = "OpenID provider configuration is missing an endpoint"
        raise OidcDiscoveryError(msg)
    authorize_url = _require_url(authorize_url, field="authorization endpoint", allow_insecure_http=allow_insecure_http)
    token_url = _require_url(token_url, field="token endpoint", allow_insecure_http=allow_insecure_http)

    userinfo_url = _optional_url(document, "userinfo_endpoint", "userinfo endpoint", allow_insecure_http)
    revocation_url = _optional_url(document, "revocation_endpoint", "revocation endpoint", allow_insecure_http)
    registration_url = _optional_url(document, "registration_endpoint", "registration endpoint", allow_insecure_http)

    return ServerMetadata(
        authorize_url=authorize_url,
        token_url=token_url,
        registration_url=registration_url,
        revocation_url=revocation_url,
        # An advisory list that a provider malforms should not fail discovery, so it is read leniently.
        scopes_supported=str_list(document.get("scopes_supported")),
        code_challenge_methods=_strict_str_list(document, "code_challenge_methods_supported"),
        token_endpoint_auth_methods=_strict_str_list(document, "token_endpoint_auth_methods_supported"),
        issuer=declared_issuer,
        iss_parameter_supported=document.get("authorization_response_iss_parameter_supported") is True,
        userinfo_url=userinfo_url,
    )


def preset(
    *,
    client_id: str,
    client_secret: str,
    scopes: list[str],
    metadata: ServerMetadata,
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
    allow_insecure_http: bool = False,
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a provider configuration from a discovered OpenID provider.

    It takes ``metadata`` as a parameter, so it stays synchronous and the caller can cache, validate or stub the fetch.
    Every parameter is keyword-only, so ``client_secret`` can later become optional without breaking callers.

    NOTE: Callers must always pair the returned config with :func:`identity_handler`.
    The module docstring explains why.

    ``openid`` is merged into ``scopes``, because without it the provider returns no ID token.

    PKCE is always on, with ``S256`` challenges.
    No ``nonce`` is sent, so PKCE is the only code-injection defense (RFC 9700).
    A provider whose advertised methods exclude ``S256`` is therefore refused, not configured without PKCE.
    A provider that advertises no methods still gets PKCE, with a WARNING.
    PKCE binds the code only if the provider enforces it.

    Args:
        client_id: The OAuth client identifier registered at the provider.
        client_secret: The OAuth client secret paired with it.
        scopes: Scopes to request, merged with the required ``openid`` scope.
        metadata: The provider's discovered metadata, from :func:`discover`.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters.
            No defaults are merged under them, because a generic connection has no product-specific behavior to fix.
        allow_insecure_http: Accept ``http`` URLs in ``metadata`` for local development, logging a WARNING for each one.

    Returns:
        The provider configuration, paired with a standard RFC 7009 revocation handler.
        The handler is ``None`` when the provider advertises no revocation endpoint.

    Raises:
        ConfigurationError: If ``client_secret`` is empty,
            or the metadata names no issuer or holds a URL that :func:`discover` would refuse.
            It is also raised if the provider advertises only token-endpoint auth methods this library cannot perform,
            or code-challenge methods that exclude ``S256``.
            These are configuration faults, not discovery failures, so they do not raise :class:`OidcDiscoveryError`.
    """
    if not client_secret.strip():
        msg = "OpenID provider preset needs a client secret, because it configures a confidential client"
        raise ConfigurationError(msg)
    if metadata.issuer is None:
        msg = "OpenID provider metadata names no issuer; an ID token's iss could not be validated"
        raise ConfigurationError(msg)
    try:
        _require_metadata_urls(metadata, allow_insecure_http=allow_insecure_http)
    except OidcDiscoveryError as exc:
        raise ConfigurationError(str(exc)) from exc

    merged_scopes = sorted(set(BASE_SCOPES) | set(scopes))
    methods = metadata.code_challenge_methods
    if methods and "S256" not in methods:
        msg = "OpenID provider advertises no S256 code-challenge method; PKCE cannot be negotiated"
        raise ConfigurationError(msg)
    if not methods:
        logger.warning(
            "OpenID provider %s does not advertise PKCE support; PKCE is still used, "
            "but it binds the authorization code only if the provider enforces it",
            metadata.issuer,
        )

    config = ProviderConfig(
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        authorize_url=metadata.authorize_url,
        token_url=metadata.token_url,
        revocation_url=metadata.revocation_url,
        redirect_uri=redirect_uri,
        scopes=merged_scopes,
        use_pkce=True,
        token_endpoint_auth_method=_select_auth_method(metadata.token_endpoint_auth_methods),
        extra_params=dict(extra_params) if extra_params else {},
        scope_metadata=BASE_SCOPE_METADATA,
        issuer=metadata.issuer,
        require_iss=metadata.iss_parameter_supported,
        # OpenID Connect standardizes no claim for an organization owning an email domain.
        can_assert_domain_ownership=False,
        # A built-in provider's handler would change ``provider`` and so every user's ``identity_key()``.
        allow_identity_inference=False,
    )
    # Revocation ending the user's consent is a per-product fact, so callers fall back to provider-side removal.
    return config, StandardRevocationHandler() if metadata.revocation_url else None


def identity_handler(
    metadata: ServerMetadata,
    *,
    transport_factory: TransportFactory | None = None,
    trust_email_verified: bool = False,
    allow_insecure_http: bool = False,
) -> OidcIdentityHandler:
    """Build the identity handler for a discovered provider.

    NOTE: Callers must always pass it to :class:`~apron_auth.client.OAuthClient`.
    The module docstring explains why.

    Args:
        metadata: The provider's discovered metadata, from :func:`discover`.
        transport_factory: Optional factory controlling the outbound connection for the userinfo request.
        trust_email_verified: Report the issuer's ``email_verified`` claim on the profile.
            It is off by default, so ``email_verified`` is ``None``
            and :meth:`~apron_auth.models.IdentityProfile.verified_email` returns nothing.
            On a self-run IdP the claim is whatever its admin set.
            Enabling this means "I trust this issuer's admin to verify addresses".
            A multi-tenant application must not enable it for a tenant-supplied issuer,
            because one tenant could assert an address in another tenant's domain.
            Key users on ``identity_key()`` instead.
        allow_insecure_http: Accept an ``http`` issuer and userinfo endpoint for local development.
            Each one logs a WARNING.

    Returns:
        The identity handler for this provider.

    Raises:
        ConfigurationError: If the metadata names no issuer,
            or its issuer or userinfo endpoint is a URL that :func:`discover` would refuse.
    """
    if metadata.issuer is None:
        msg = "OpenID provider metadata names no issuer; an identity handler could not be bound to one"
        raise ConfigurationError(msg)
    return OidcIdentityHandler(
        issuer=metadata.issuer,
        userinfo_url=metadata.userinfo_url,
        transport_factory=transport_factory,
        trust_email_verified=trust_email_verified,
        allow_insecure_http=allow_insecure_http,
    )


class OidcIdentityHandler:
    """Establish identity from an ID token's claims and the userinfo endpoint.

    The handler is bound to one issuer, and it refuses a config that names another.

    The ID token is the trust-bearing source.
    Its ``iss``, ``aud``, ``azp``, ``exp`` and ``sub`` are validated before any claim is read.
    ``sub`` is taken from it in preference to userinfo, because the caller makes access decisions on it.
    Userinfo supplies display fields, and it stands in entirely when the provider returns no ID token.
    OpenID Connect Core 1.0 section 3.1.3.3 requires an ID token when ``openid`` was requested.
    A provider that omits it is out of spec, but userinfo still says who signed in, with a weaker guarantee.

    When an ID token validated, the userinfo call only adds detail.
    If it fails, a WARNING is logged and identity rests on the ID token.
    With no usable ID token, userinfo is the only source, so its failure raises.

    NOTE: Callers must pass only tokens taken from a token-endpoint response over TLS,
    never a stored or front-channel token.
    The ID token is validated without a signature check, which is safe only on that channel.

    A userinfo response whose ``sub`` is missing or differs from the ID token's is refused, not reconciled.
    OpenID Connect Core 1.0 section 5.3.2 requires the two to match.
    """

    def __init__(
        self,
        *,
        issuer: str,
        userinfo_url: str | None,
        transport_factory: TransportFactory | None = None,
        trust_email_verified: bool = False,
        allow_insecure_http: bool = False,
    ) -> None:
        """Bind this handler to an issuer and configure where it reads userinfo from.

        Args:
            issuer: The issuer this handler serves. It refuses a config that names any other issuer.
            userinfo_url: The provider's userinfo endpoint.
                It is ``None`` when the provider advertises none, and identity then rests on the ID token alone.
            transport_factory: Optional factory controlling the outbound connection for the userinfo request.
            trust_email_verified: Report the issuer's ``email_verified`` claim, as :func:`identity_handler` describes.
                When ``False``, the claim is reported as ``None``.
            allow_insecure_http: Accept an ``http`` issuer and userinfo endpoint for local development.
                Each one logs a WARNING.

        Raises:
            ConfigurationError: If the issuer or the userinfo endpoint is a URL that :func:`discover` would refuse.
        """
        try:
            _require_url(issuer, field="issuer", allow_insecure_http=allow_insecure_http, is_issuer=True)
            if userinfo_url is not None:
                _require_url(userinfo_url, field="userinfo endpoint", allow_insecure_http=allow_insecure_http)
        except OidcDiscoveryError as exc:
            raise ConfigurationError(str(exc)) from exc
        self._issuer = issuer
        self._trust_email_verified = trust_email_verified
        self._userinfo_url = userinfo_url
        self._transport_factory = transport_factory

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields for a generic OpenID sign-in.

        Args:
            material: The access token, and the ID token whose validated claims are preferred where they overlap.
            config: The provider configuration the tokens were issued under.
                The ID token is validated against its ``issuer`` and ``client_id``.

        Returns:
            The identity profile.
            ``provider`` is namespaced by issuer, and ``tenancies`` is always empty.

        Raises:
            ConfigurationError: If ``config`` names no issuer, or names one other than this handler's.
                Either way, no request is sent.
            IdentityScopeNotGrantedError: If there is no usable ID token,
                and the userinfo endpoint answers 403 ``insufficient_scope`` (RFC 6750).
            IdentityFetchError: If the ID token's claims do not validate or its ``sub`` is not a non-empty string.
                It is also raised when userinfo fails and there is no validated ID token,
                when userinfo names no subject or a different one than the ID token, or when neither yields a subject.
        """
        if config.issuer is None:
            msg = "OpenID provider config names no issuer; an ID token's iss could not be validated"
            raise ConfigurationError(msg)
        if config.issuer != self._issuer:
            msg = "OpenID identity handler was built for a different issuer than the provider config names"
            raise ConfigurationError(msg)
        issuer = config.issuer
        claims = (
            self._validated_claims(material.id_token, material.access_token, issuer, config.client_id)
            if material.id_token
            else None
        )
        userinfo: dict[str, Any] = {}
        userinfo_fetched = False
        if self._userinfo_url:
            try:
                userinfo = await self._fetch_userinfo(self._userinfo_url, material.access_token)
                userinfo_fetched = True
            except IdentityFetchError as exc:
                if claims is None:
                    raise
                # Userinfo only enriches a subject the ID token already gave.
                logger.warning("OpenID userinfo request failed, identity rests on the ID token alone: %s", exc)

        claims_subject = _claim_str(claims, "sub")
        if claims is not None and claims_subject is None:
            # Authlib only requires ``sub`` to be present, so a non-string would read as a userinfo mismatch.
            msg = "OpenID ID token has an invalid sub claim"
            raise IdentityFetchError(msg)
        subject = claims_subject or _claim_str(userinfo, "sub")
        if subject is None:
            msg = "OpenID sign-in returned no subject"
            raise IdentityFetchError(msg)
        if claims is not None and userinfo_fetched:
            # Section 5.3.2: userinfo ``sub`` must match the ID token's, and an absent one does not.
            userinfo_subject = _claim_str(userinfo, "sub")
            if userinfo_subject is None:
                msg = "OpenID userinfo response names no subject to match the ID token's"
                raise IdentityFetchError(msg)
            if userinfo_subject != claims_subject:
                msg = "OpenID userinfo response names a different subject than the ID token"
                raise IdentityFetchError(msg)

        email, email_verified = _email_fields(claims, userinfo)
        if not self._trust_email_verified:
            email_verified = None
        return IdentityProfile(
            provider=_provider_name(issuer),
            subject=subject,
            email=email,
            email_verified=email_verified,
            name=_claim_str(claims, "name") or _claim_str(userinfo, "name"),
            username=_claim_str(claims, "preferred_username") or _claim_str(userinfo, "preferred_username"),
            avatar_url=_claim_str(claims, "picture") or _claim_str(userinfo, "picture"),
            tenancies=(),
            # Keyed rather than merged, so a caller can tell issuer-asserted claims from userinfo's.
            raw={"id_token": claims or {}, "userinfo": userinfo},
        )

    def _validated_claims(self, id_token: str, access_token: str, issuer: str, client_id: str) -> dict[str, Any] | None:
        """Return the ID token's claims once they check out.

        Claims are validated per OpenID Connect Core 1.0 section 3.1.3.7.
        ``iss``, ``sub``, ``aud``, ``exp`` and ``iat`` are essential.
        ``azp`` is required when the audience is not solely this client.
        ``at_hash`` is checked against the access token.
        The signature is not checked, as the module docstring explains.

        A token that is not a parseable JWT gives ``None``, and identity falls back to userinfo.
        The provider has still authenticated somebody, and userinfo says who.
        A token that parses but has wrong claims raises, because it was minted for someone else or by someone else.

        Args:
            id_token: The ID token from the token-endpoint response.
            access_token: The access token from the same response.
                A present ``at_hash`` is verified against it.
            issuer: The issuer the token's ``iss`` must name.
            client_id: The client identifier the token's ``aud`` must name.

        Returns:
            The validated claims, or ``None`` when the token is unparseable.

        Raises:
            IdentityFetchError: If any claim does not validate.
        """
        try:
            signature = jws.extract_compact(id_token.encode())
            claims = json.loads(signature.payload)
        except (JoseError, ValueError):
            logger.warning("OpenID ID token dropped, identity falls back to userinfo: token is not a parseable JWT")
            return None
        if not isinstance(claims, dict):
            logger.warning("OpenID ID token dropped, identity falls back to userinfo: payload was not a JSON object")
            return None
        token = CodeIDToken(
            claims,
            # The real header: ``at_hash`` validation reads ``alg`` from it.
            signature.headers(),
            # ``CodeIDToken`` does not compare ``aud`` to ``client_id`` itself, so it is declared here.
            {
                "iss": {"values": [issuer], "essential": True},
                "aud": {"values": [client_id], "essential": True},
            },
            {"client_id": client_id, "access_token": access_token},
        )
        try:
            token.validate(leeway=_CLOCK_SKEW_SECONDS)
        except ClaimError as exc:
            raise IdentityFetchError(_claim_error_message(exc)) from exc
        except (JoseError, TypeError, ValueError) as exc:
            # A malformed header or claim shape can raise ``TypeError``, which must surface as ``IdentityFetchError``.
            msg = "OpenID ID token claims did not validate"
            raise IdentityFetchError(msg) from exc
        # OpenID Connect Core 1.0 section 2 makes ``iss`` one string, but the validator accepts a list holding it.
        if claims.get("iss") != issuer:
            msg = "OpenID ID token has an invalid iss claim"
            raise IdentityFetchError(msg)
        return claims

    async def _fetch_userinfo(self, userinfo_url: str, access_token: str) -> dict[str, Any]:
        """Fetch the userinfo payload for display fields.

        Args:
            userinfo_url: The userinfo endpoint.
            access_token: The bearer access token for the userinfo request.

        Returns:
            The userinfo payload as a JSON object.

        Raises:
            IdentityScopeNotGrantedError: If the endpoint answers 403 ``insufficient_scope``.
            IdentityFetchError: If the transport factory refuses the connection, the request fails,
                or the response is signed, cannot be parsed, or is not a JSON object.
        """
        try:
            transport = self._transport_factory(userinfo_url) if self._transport_factory is not None else None
        except Exception as exc:
            # The factory is caller code, so any exception from it means the connection was refused.
            raise IdentityFetchError("Failed to fetch OpenID identity: outbound connection refused") from exc
        try:
            async with httpx.AsyncClient(transport=transport, timeout=_USERINFO_TIMEOUT) as client:
                response = await client.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if (
                exc.response.status_code == 403
                and _bearer_error(exc.response.headers.get("www-authenticate", "")) == "insufficient_scope"
            ):
                raise IdentityScopeNotGrantedError("OpenID userinfo refused the token: insufficient_scope") from exc
            raise IdentityFetchError(f"Failed to fetch OpenID identity: {describe_http_error(exc)}") from exc
        except httpx.RequestError as exc:
            raise IdentityFetchError(f"Failed to fetch OpenID identity: {describe_http_error(exc)}") from exc
        except httpx.InvalidURL as exc:
            raise IdentityFetchError("Failed to fetch OpenID identity: invalid userinfo URL") from exc

        media_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if media_type == "application/jwt":
            # Signatures are not verified here, so a signed response is refused rather than read unverified.
            msg = "OpenID provider returned a signed userinfo response, which is not supported"
            raise IdentityFetchError(msg)
        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError("Failed to parse OpenID identity response") from exc
        if not isinstance(payload, dict):
            msg = "OpenID identity response was not a JSON object"
            raise IdentityFetchError(msg)
        return payload


# These patterns match the ``WWW-Authenticate`` grammar of RFC 9110 section 11.6.1.
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
# The header arrives decoded as text, so obs-text matches any non-ASCII character.
_QUOTED_STRING = r'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\U0010ffff]|\\[\t \x21-\x7e\x80-\U0010ffff])*"'
_AUTH_PARAM = re.compile(rf"({_TOKEN})[ \t]*=[ \t]*({_TOKEN}|{_QUOTED_STRING})")
_AUTH_SCHEME = re.compile(_TOKEN)
_TOKEN68 = re.compile(r"[0-9A-Za-z._~+/-]+=*")


class _ChallengeElement(Enum):
    """Each member is one kind of element in a ``WWW-Authenticate`` header."""

    AUTH_PARAM = auto()
    AUTH_SCHEME = auto()
    TOKEN68 = auto()


def _bearer_error(header: str) -> str | None:
    """Return the ``error`` parameter of a ``WWW-Authenticate`` header's ``Bearer`` challenge.

    The header must parse in full as RFC 9110 section 11.6.1 challenges, so a malformed header never yields a code.
    Text inside another parameter or another scheme's challenge is never read as the code (RFC 6750 section 3).

    Args:
        header: The ``WWW-Authenticate`` header value, which may hold several challenges.

    Returns:
        The error code, or ``None`` when the header does not parse or has no single ``Bearer`` error code.
    """
    error: str | None = None
    scheme: str | None = None
    previous: _ChallengeElement | None = None
    position = 0
    while True:
        start = position
        while position < len(header) and header[position] in " \t,":
            position += 1
        separator = header[start:position]
        if position == len(header):
            return error
        has_comma = "," in separator
        # Credentials follow their scheme after spaces, and a comma straight after the scheme ends the challenge.
        opens_credentials = (
            previous is _ChallengeElement.AUTH_SCHEME
            and separator.startswith(" ")
            and (has_comma or not separator.strip(" "))
        )
        if param := _AUTH_PARAM.match(header, position):
            if not (opens_credentials or (previous is _ChallengeElement.AUTH_PARAM and has_comma)):
                return None
            name, value = param.groups()
            if scheme == "bearer" and name.lower() == "error":
                if error is not None:
                    return None
                error = re.sub(r"\\(.)", r"\1", value[1:-1]) if value.startswith('"') else value
            previous, position = _ChallengeElement.AUTH_PARAM, param.end()
        elif opens_credentials and not has_comma and (token68 := _TOKEN68.match(header, position)):
            previous, position = _ChallengeElement.TOKEN68, token68.end()
        elif (previous is None or has_comma) and (challenge := _AUTH_SCHEME.match(header, position)):
            scheme = challenge.group().lower()
            previous, position = _ChallengeElement.AUTH_SCHEME, challenge.end()
        else:
            return None


def _claim_error_message(exc: ClaimError) -> str:
    """Our own wording for a failed claim, naming the claim and never its value.

    Args:
        exc: The validator's claim error, which carries the claim name and kind.

    Returns:
        The message to raise.
    """
    kind = getattr(exc, "error", "invalid_claim")
    if kind == "missing_claim":
        return f"OpenID ID token is missing the {exc.claim} claim"
    if kind == "expired_token":
        return "OpenID ID token has expired"
    return f"OpenID ID token has an invalid {exc.claim} claim"


def _provider_name(issuer: str) -> str:
    """The ``IdentityProfile.provider`` string for a generic OpenID connection.

    The string carries the issuer.
    A ``sub`` is unique only within one issuer (OpenID Connect Core 1.0, section 2).
    With a bare ``"oidc"``, two issuers could collide on the ``(provider, subject)`` pair.
    That pair is what :meth:`~apron_auth.models.IdentityProfile.identity_key` returns.

    Args:
        issuer: The validated issuer identifier.

    Returns:
        The provider string, of the form ``oidc:<issuer>``.
    """
    return f"oidc:{issuer}"


def _email_fields(claims: dict[str, Any] | None, userinfo: dict[str, Any]) -> tuple[str | None, bool | None]:
    """The ``email`` and ``email_verified`` pair, taken from a single document.

    Both fields come from one source: the ID token when it carries an ``email``, and userinfo otherwise.
    They are one assertion, so an address from one document never pairs with a verification flag from the other.

    ``email_verified`` is honored only as a JSON boolean, because a bare ``bool()`` reads ``"false"`` as ``True``.
    It is ``None`` when the chosen document omits it, because an unasserted value differs from an asserted ``false``.
    An ``email_verified`` with no ``email`` beside it asserts nothing and is dropped.

    Args:
        claims: The validated ID-token claims, or ``None`` when absent.
        userinfo: The userinfo payload, empty when none was fetched.

    Returns:
        The address and its verification flag, both from one document.
        It is ``(None, None)`` when neither document carries an address.
    """
    for source in (claims, userinfo):
        if source is None:
            continue
        email = _claim_str(source, "email")
        if email is None:
            continue
        verified = source.get("email_verified")
        return email, verified if isinstance(verified, bool) else None
    return None, None


def _claim_str(source: dict[str, Any] | None, name: str) -> str | None:
    """Return a claim when it is a non-empty string, else ``None``."""
    if source is None:
        return None
    value = source.get(name)
    return value if isinstance(value, str) and value else None


def _strict_str_list(document: dict[str, Any], key: str) -> list[str]:
    """Return a security-relevant list member, refusing a malformed one.

    A present but malformed value is an error, because these lists gate a refusal.
    Treating ``"plain"`` as "not advertised" would take the permissive branch.

    Args:
        document: The configuration document.
        key: The member to read.

    Returns:
        The strings, or ``[]`` when the member is absent.

    Raises:
        OidcDiscoveryError: If the member is present but not a list of strings.
    """
    value = document.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        msg = f"OpenID provider configuration has a malformed {key}"
        raise OidcDiscoveryError(msg)
    return value


def _select_auth_method(advertised: Sequence[str]) -> str:
    """Choose the token-endpoint auth method for a confidential client.

    Prefers ``client_secret_post`` among the methods the provider advertises.
    When the provider advertises none, it uses ``client_secret_basic``.
    That is the default in OpenID Connect Discovery 1.0 section 3.
    RFC 6749 section 2.3.1 also requires every server to support that method.

    Args:
        advertised: The methods the provider advertises support for.

    Returns:
        The method to authenticate the token request with.

    Raises:
        ConfigurationError: If the provider advertises only methods this library cannot perform.
            The document is valid, so this is a configuration error, not a discovery failure.
    """
    if not advertised:
        return TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
    for method in CONFIDENTIAL_AUTH_METHODS:
        if method in advertised:
            return method
    msg = "OpenID provider advertises no token-endpoint auth method this library can perform"
    raise ConfigurationError(msg)


def _require_url(value: Any, *, field: str, allow_insecure_http: bool, is_issuer: bool = False) -> str:
    """Require ``value`` to be an absolute URL this module may talk to.

    This is the one URL rule for the issuer, the document URL and every endpoint.
    The value must be a string with a scheme, a host and no fragment.
    It must use ``https`` unless ``allow_insecure_http`` is set.
    An issuer also has no query and no userinfo (OpenID Connect Discovery 1.0 section 4.1).

    Args:
        value: The raw value to check.
        field: What the value is, for the error and the warning.
        allow_insecure_http: Let an ``http`` URL through, logging a WARNING.
        is_issuer: Apply the stricter issuer rules.

    Returns:
        ``value``, once it passes.

    Raises:
        OidcDiscoveryError: If ``value`` is not an acceptable URL.
    """
    if not isinstance(value, str) or not value:
        msg = f"OpenID {field} is not an absolute URL"
        raise OidcDiscoveryError(msg)
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
    except ValueError as exc:
        msg = f"OpenID {field} is malformed"
        raise OidcDiscoveryError(msg) from exc
    if not parsed.scheme or not hostname:
        msg = f"OpenID {field} is not an absolute URL"
        raise OidcDiscoveryError(msg)
    scheme = parsed.scheme.lower()
    if scheme == "http" and allow_insecure_http:
        logger.warning("OpenID %s is plain http; allowed by allow_insecure_http, use for local development only", field)
    elif scheme != "https":
        msg = f"OpenID {field} must use https (pass allow_insecure_http=True for local development)"
        raise OidcDiscoveryError(msg)
    if "#" in value:
        msg = f"OpenID {field} must not carry a fragment"
        raise OidcDiscoveryError(msg)
    if is_issuer and "?" in value:
        msg = f"OpenID {field} must not carry a query"
        raise OidcDiscoveryError(msg)
    if is_issuer and "@" in parsed.netloc:
        msg = f"OpenID {field} must not carry userinfo"
        raise OidcDiscoveryError(msg)
    return value


def _require_metadata_urls(metadata: ServerMetadata, *, allow_insecure_http: bool) -> None:
    """Require every URL in ``metadata`` to meet the rule :func:`discover` applies.

    Args:
        metadata: The metadata to check.
        allow_insecure_http: Accept ``http`` URLs, logging a WARNING for each one.

    Raises:
        OidcDiscoveryError: If any URL is not acceptable.
    """
    _require_url(metadata.issuer, field="issuer", allow_insecure_http=allow_insecure_http, is_issuer=True)
    _require_url(metadata.authorize_url, field="authorization endpoint", allow_insecure_http=allow_insecure_http)
    _require_url(metadata.token_url, field="token endpoint", allow_insecure_http=allow_insecure_http)
    optional_urls = (
        ("registration endpoint", metadata.registration_url),
        ("revocation endpoint", metadata.revocation_url),
        ("userinfo endpoint", metadata.userinfo_url),
    )
    for field, url in optional_urls:
        if url is not None:
            _require_url(url, field=field, allow_insecure_http=allow_insecure_http)


def _optional_url(document: dict[str, Any], key: str, field: str, allow_insecure_http: bool) -> str | None:
    """Validate an optional endpoint when the document names one.

    Args:
        document: The configuration document.
        key: The document member to read.
        field: What the endpoint is, for errors.
        allow_insecure_http: Passed through to :func:`_require_url`.

    Returns:
        The endpoint, or ``None`` when the document omits it or gives an empty string.

    Raises:
        OidcDiscoveryError: If the member is present and not empty, but not an acceptable URL.
    """
    value = document.get(key)
    if value is None or value == "":
        return None
    return _require_url(value, field=field, allow_insecure_http=allow_insecure_http)


async def _fetch_document(url: str, transport_factory: TransportFactory | None) -> dict[str, Any]:
    """Fetch the configuration document at ``url``.

    Redirects are not followed, so the request goes to ``url`` and nowhere else.

    Args:
        url: The document URL, already validated.
        transport_factory: Optional factory controlling the outbound connection.

    Returns:
        The document as a JSON object.

    Raises:
        OidcDiscoveryError: If the transport factory refuses the connection, the request fails,
            the response is not HTTP 200, or its body is not a JSON object.
    """
    try:
        client = discovery_client(url, transport_factory)
    except Exception as exc:
        # Building the client calls the caller's transport factory, so any exception here means a refused connection.
        msg = "could not fetch the OpenID provider configuration (outbound connection refused)"
        raise OidcDiscoveryError(msg) from exc
    async with client:
        try:
            response = await client.get(url)
        except httpx.RequestError as exc:
            msg = f"could not fetch the OpenID provider configuration ({describe_http_error(exc)})"
            raise OidcDiscoveryError(msg) from exc
        except httpx.InvalidURL as exc:
            msg = "could not fetch the OpenID provider configuration (invalid URL)"
            raise OidcDiscoveryError(msg) from exc
        if response.status_code != 200:
            if 300 <= response.status_code < 400:
                # The target is provider-controlled text, so it is not logged.
                logger.debug("OpenID provider configuration returned HTTP %s", response.status_code)
                msg = (
                    f"OpenID provider configuration returned HTTP {response.status_code}; redirects are not "
                    "followed, so pass the canonical document URL as document_url"
                )
                raise OidcDiscoveryError(msg)
            msg = f"OpenID provider configuration returned HTTP {response.status_code}"
            raise OidcDiscoveryError(msg)
        try:
            document = response.json()
        except ValueError as exc:
            msg = "OpenID provider configuration was not JSON"
            raise OidcDiscoveryError(msg) from exc
    if not isinstance(document, dict):
        msg = "OpenID provider configuration was not a JSON object"
        raise OidcDiscoveryError(msg)
    return document


__all__ = [
    "BASE_SCOPES",
    "BASE_SCOPE_METADATA",
    "OidcIdentityHandler",
    "discover",
    "discovery_url",
    "identity_handler",
    "preset",
]
