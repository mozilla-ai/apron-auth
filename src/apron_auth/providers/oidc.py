"""Generic OpenID Connect provider preset, discovery, and identity handler.

The preset every other module in this package is not: it names no endpoints,
because it has none to name. An OpenID provider publishes its own configuration
document, so :func:`discover` reads the endpoints from the issuer and
:func:`preset` folds them together with a client identity. That covers Keycloak,
Okta, Auth0, Entra ID, Authentik, Zitadel, Dex, Ping, and anything else that
implements OpenID Connect Discovery 1.0, without a module here per product.

**Always pass the identity handler explicitly.** This module registers no
identity resolver, but host-based inference still runs on the config
:func:`preset` returns: a generic config whose endpoints sit on a host another
provider claims (an Entra or Google issuer, say) is resolved to that provider's
handler by ``providers.identity.infer_identity_handler``. ``provider`` is then
``microsoft`` or ``google`` rather than ``oidc:<issuer>``, and adding the
explicit handler later changes every user's ``identity_key()``. Pass
:func:`identity_handler` to :class:`~apron_auth.client.OAuthClient` from the
start; skipping generic configs in inference is tracked as a follow-up (#137).

**ID-token signatures are not verified here, and that is compliant rather than
a shortcut.** The tokens this module sees arrive on the token-endpoint response
over the back-channel, where TLS already authenticates the issuer; OpenID
Connect Core 1.0 section 3.1.3.7 permits TLS server validation in place of a
signature check for exactly that case, and ``providers.microsoft`` already
relies on it. What is *not* optional is validating the claims, and that is
delegated to :class:`authlib.oidc.core.CodeIDToken` — authlib's own
implementation of the section 3.1.3.7 rules, the same validator its OpenID
client uses — which checks ``iss``, ``sub``, ``aud``, ``exp``, ``iat``,
``azp`` and ``at_hash`` (the last against the access token it was minted
over, per section 3.1.3.7 step 8). :class:`OidcIdentityHandler` then refuses
a userinfo response whose ``sub`` disagrees with the ID token's (section
5.3.2).

Deliberate limitations
----------------------

Each of these is a decision, not an oversight, and each is the thing to change
first if a deployment needs it.

* **Confidential clients only.** :func:`preset` requires a client secret, and
  :func:`_select_auth_method` never returns ``none``. A public client — the
  ordinary shape for native and single-page apps — cannot be configured, even
  though :class:`~apron_auth.models.ProviderConfig` models one. Supporting it
  is a change to this module's signature, not to the flow.
* **No ``nonce``, and no per-request authorization parameters** (``prompt``,
  ``login_hint``, ``max_age``, ``acr_values``, ``ui_locales``, ``display``,
  ``id_token_hint``). ``nonce`` is OPTIONAL for the authorization-code flow
  (section 3.1.2.1), so omitting it is compliant, but it means PKCE is the only
  code-injection defense and holds only where the provider enforces PKCE.
  What blocks all of them alike is that ``extra_params`` is fixed on
  a frozen config: a ``nonce`` threaded through it would be the same constant on
  every request, which defeats the replay defense rather than providing it.
  These need per-request support in
  :meth:`~apron_auth.client.OAuthClient.get_authorization_url` and
  :class:`~apron_auth.models.OAuthPendingState`, not a knob here.
* **No RP-Initiated Logout.** ``end_session_endpoint`` is neither read from the
  configuration document nor carried on :class:`ServerMetadata`.
* **No ``response_mode``.** The query default is always used.
* **A token response without an ``id_token`` is accepted**, degrading to
  userinfo alone. Section 3.1.3.3 requires one on a flow that requested
  ``openid``, so such a provider is out of spec; identity is still established,
  with a weaker claim to have vouched for it.
* **A signed (``application/jwt``) userinfo response is refused**, not read
  unverified — see :meth:`OidcIdentityHandler._fetch_userinfo`.
* **HTTPS is required.** The issuer, the document URL and every endpoint a
  configuration document names must be ``https``, because the unsigned-token
  design above rests on TLS authenticating the issuer. :func:`discover` takes
  an explicit ``allow_insecure_http`` opt-in for local development, which logs
  a WARNING. Host policy is separate and stays with ``transport_factory``.
* **RP-Initiated Logout is not wired up**, though
  ``authlib.integrations.base_client`` implements it in ``create_logout_url``
  should this module ever grow it.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
from authlib.oidc.core import CodeIDToken
from authlib.oidc.discovery import get_well_known_url
from joserfc import jws
from joserfc.errors import ClaimError, JoseError
from pydantic import SecretStr

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

if TYPE_CHECKING:
    from collections.abc import Sequence

    from apron_auth.protocols import RevocationHandler, TransportFactory


logger = logging.getLogger(__name__)

_DISCOVERY_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_USERINFO_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Token-endpoint auth methods this library can perform for a confidential
# client, in the order it prefers them. authlib drives both.
_CONFIDENTIAL_AUTH_METHODS = (
    TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
)

# Clock skew allowed when checking an ID token's ``exp``. The token is read
# seconds after the issuer minted it, so this covers a provider whose clock runs
# behind rather than a token that has genuinely aged.
_EXPIRY_LEEWAY_SECONDS = 60


# RFC 6750 section 3: ``error="insufficient_scope"`` in ``WWW-Authenticate``.
_INSUFFICIENT_SCOPE = re.compile(r'error\s*=\s*"?insufficient_scope"?', re.IGNORECASE)

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
    """The configuration document's URL for ``issuer``.

    Delegates to :func:`authlib.oidc.discovery.get_well_known_url`, which
    appends the well-known suffix to the issuer *including its path* as OpenID
    Connect Discovery 1.0 section 4 requires — so a Keycloak realm at
    ``https://sso.example.com/realms/acme`` publishes at
    ``https://sso.example.com/realms/acme/.well-known/openid-configuration``
    rather than at the host root, and a trailing slash on the issuer does not
    produce a doubled one. Kept as a thin named wrapper because it is part of
    this module's public surface and because ``external=True`` (absolute URL
    rather than path-only) is the non-obvious half of the call.

    The parse guard stays ours: ``get_well_known_url`` concatenates without
    validating, so a malformed issuer would otherwise surface later as a
    malformed *URL* and lose which input was actually at fault. The guard
    checks that the issuer is an absolute URL — a scheme and a host, not a
    bare hostname, with no query, fragment or userinfo — because appending a well-known suffix to a relative
    string produces a relative URL that no client can fetch. The scheme must
    be ``https`` unless ``allow_insecure_http`` is set; see :func:`discover`.

    Args:
        issuer: The issuer identifier to derive the document URL from.
        allow_insecure_http: Accept an ``http`` issuer, for local development.

    Returns:
        The configuration document's URL.

    Raises:
        OidcDiscoveryError: If ``issuer`` is not a parseable absolute URL, has
            a query, fragment or userinfo, or is not ``https`` and
            ``allow_insecure_http`` is unset.
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

    The document's own ``issuer`` is compared against ``issuer`` and a mismatch
    is refused (OpenID Connect Discovery 1.0, section 4.3). That check is what
    makes the issuer a trust anchor rather than a hostname: without it, a
    document served from anywhere could name any issuer, and every later
    ``iss`` validation would be measuring against the attacker's own answer.

    Args:
        issuer: The issuer identifier, which the document must also name. This
            is the value an operator configures, and the one an authorization
            response's ``iss`` is later checked against.
        document_url: Where to fetch the document, when it is not at the
            standard suffix :func:`discovery_url` derives. The issuer check
            still applies, so an override relocates the document without
            loosening what it may claim.
        transport_factory: Optional factory returning an httpx transport for
            the document URL, letting the caller control the outbound
            connection. This is where network policy belongs: no host check is
            applied here, because whether a given issuer may be reached is the
            deployment's question, not this library's, and a check that inspects
            only the URL string cannot answer it anyway — a hostname resolving
            to an internal address passes any such test.
        allow_insecure_http: Accept ``http`` for the issuer, the document URL
            and the endpoints the document names. Off by default, because ID
            tokens are not signature-checked and rely on TLS to authenticate the
            issuer; over ``http`` an on-path attacker chooses every claim and
            reads the client secret. Intended for local development only, and
            logs a WARNING for each URL it lets through.

    Returns:
        The discovered metadata, carrying the userinfo endpoint alongside the
        authorization-code flow's own.

    Raises:
        OidcDiscoveryError: If the issuer is malformed, the issuer, document
            URL or an endpoint is not ``https`` (and ``allow_insecure_http`` is
            unset), the document cannot be fetched or parsed, it omits an
            endpoint the flow requires, or it names an issuer other than
            ``issuer``.
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
    # Compared exactly rather than normalized. RFC 8414 section 2 makes the
    # issuer a URL with no trailing slash, and two values that differ only by
    # one are two different strings to every ``iss`` comparison downstream; a
    # normalization here would hide the discrepancy rather than resolve it.
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
        scopes_supported=_str_list(document.get("scopes_supported")),
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
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a provider configuration from a discovered OpenID provider.

    Takes ``metadata`` where every other preset hardcodes endpoints. Making it a
    parameter rather than an implicit fetch keeps this function synchronous and
    keeps the network call somewhere a caller can cache, validate, or stub.
    Every parameter is keyword-only, so making ``client_secret`` optional later
    (for public clients) is not a breaking change.

    The returned config must always be paired with :func:`identity_handler`.
    Without an explicit handler, host-based inference can resolve a config on a
    host another provider claims (an Entra or Google issuer) to that
    provider's handler, which changes ``provider`` and every user's
    ``identity_key()``; see the module docstring.

    ``openid`` is merged into ``scopes``: without it the provider runs a plain
    OAuth flow, returns no ID token, and nothing below can establish an
    identity.

    PKCE is always on. :class:`~apron_auth.client.OAuthClient` issues only
    ``S256`` challenges, so a provider advertising code-challenge methods that
    exclude ``S256`` is refused rather than configured without PKCE. The
    refusal is the point: this module sends no ``nonce`` (OpenID Connect Core
    1.0 section 3.1.2.1 makes it OPTIONAL for the authorization-code flow), so
    PKCE is the *only* thing binding an authorization code to the session that
    requested it. Silently clearing it would hand back a config with no
    code-injection defense at all, which RFC 9700 requires a client to prevent
    by one mechanism or the other. A provider advertising no methods still gets
    PKCE, with a WARNING: some real providers (Entra) omit the field, but one
    that does not implement PKCE ignores the challenge, leaving the code
    unbound to the session.

    Args:
        client_id: The OAuth client identifier registered at the provider.
        client_secret: The OAuth client secret paired with it.
        scopes: Scopes to request; merged with the required ``openid`` scope.
        metadata: The provider's discovered metadata, from :func:`discover`.
        redirect_uri: The redirect URI for the authorization flow.
        extra_params: Extra authorization-request parameters. No defaults are
            merged under these: a generic connection has no product-specific
            consent behavior to compensate for, and an unexpected parameter on
            an arbitrary provider's authorization request is more likely to be
            refused than ignored.

    Returns:
        The provider configuration, paired with a standard RFC 7009 revocation
        handler when the provider advertises a revocation endpoint and ``None``
        when it does not.

    Raises:
        ConfigurationError: If the metadata names no issuer, or if the provider
            advertises only token-endpoint auth methods this library cannot
            perform or advertises code-challenge methods that exclude
            ``S256``. None of these are failures of discovery — the document
            was read and is valid — so they raise ``ConfigurationError``
            rather than :class:`OidcDiscoveryError`, letting a caller that
            catches the latter to mean "provider unreachable" keep the
            distinction.
    """
    if metadata.issuer is None:
        msg = "OpenID provider metadata names no issuer; an ID token's iss could not be validated"
        raise ConfigurationError(msg)

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
        # A generic connection asserts no tenancy: OpenID Connect standardizes
        # no claim for "this user's organization owns this email domain", and
        # the products that do carry one (Google's ``hd``, Entra's verified
        # domains) each spell it their own way in their own module.
        can_assert_domain_ownership=False,
    )
    # Nothing here can revoke the portal-level grant: whether revocation ends
    # the user's consent is a per-product fact, and a generic connection has no
    # product to look it up for. Left False so a caller falls back to telling
    # the user to remove the application at the provider, which is always true.
    return config, StandardRevocationHandler() if metadata.revocation_url else None


def identity_handler(
    metadata: ServerMetadata,
    *,
    transport_factory: TransportFactory | None = None,
    trust_email_verified: bool = False,
) -> OidcIdentityHandler:
    """Build the identity handler for a discovered provider.

    The counterpart to the inference every other provider gets for free from
    ``providers.identity``; always pass it to
    :class:`~apron_auth.client.OAuthClient`, as the module docstring explains.
    The issuer and client identifier an ID token is validated against are read
    from the :class:`~apron_auth.models.ProviderConfig` that :func:`preset`
    built, so they cannot disagree with it.

    Args:
        metadata: The provider's discovered metadata, from :func:`discover`.
        transport_factory: Optional factory controlling the outbound connection
            for the userinfo request, matching the one :func:`discover` accepts.
        trust_email_verified: Report the issuer's ``email_verified`` claim on
            the profile. Off by default, so ``email_verified`` is ``None`` and
            :meth:`~apron_auth.models.IdentityProfile.verified_email` returns
            nothing. On a self-run IdP the claim is whatever its admin set, so
            enabling this means "I trust this issuer's admin to verify
            addresses". A multi-tenant application must not enable it for a
            tenant-supplied issuer: one tenant could assert an address in
            another tenant's domain. Key users on ``identity_key()`` instead.

    Returns:
        The identity handler for this provider.
    """
    return OidcIdentityHandler(
        userinfo_url=metadata.userinfo_url,
        transport_factory=transport_factory,
        trust_email_verified=trust_email_verified,
    )


class OidcIdentityHandler:
    """Establish identity from an ID token's claims and the userinfo endpoint.

    The ID token is the trust-bearing half: its ``iss``, ``aud``, ``azp``,
    ``exp`` and ``sub`` are validated before any claim is read, and ``sub`` is
    taken from it in preference to userinfo, because that is what the caller
    makes an access decision on. Userinfo supplies display fields and stands in
    entirely when the provider returns no ID token — OpenID Connect Core 1.0
    section 3.1.3.3 requires one on a flow that requested ``openid``, so a
    provider that omits it is out of spec, but it has still authenticated
    somebody and userinfo will say who, with a weaker claim to have vouched
    for it.

    The userinfo call is enrichment when an ID token validated: if it fails,
    a WARNING is logged and identity rests on the ID token. With no usable ID
    token it is the only source, so its failure raises.

    NOTE: Callers must pass only tokens taken from a token-endpoint response
    over TLS, never a stored or front-channel token. The ID token is validated
    without a signature check, which is safe only on that channel.

    A userinfo response whose ``sub`` is missing or names a different subject
    than the ID token is refused outright rather than reconciled (OpenID Connect Core 1.0,
    section 5.3.2): the two documents disagreeing about who signed in is not a
    field to prefer between.
    """

    def __init__(
        self,
        *,
        userinfo_url: str | None,
        transport_factory: TransportFactory | None = None,
        trust_email_verified: bool = False,
    ) -> None:
        """Configure where this handler reads userinfo from.

        Args:
            userinfo_url: The provider's userinfo endpoint, or ``None`` when it
                advertises none and identity rests on the ID token alone.
            transport_factory: Optional factory controlling the outbound
                connection for the userinfo request.
            trust_email_verified: Report the issuer's ``email_verified`` claim;
                see :func:`identity_handler`. When ``False``, it is reported as
                ``None``.
        """
        self._trust_email_verified = trust_email_verified
        self._userinfo_url = userinfo_url
        self._transport_factory = transport_factory

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields for a generic OpenID sign-in.

        Args:
            material: The token material — the access token, and the ID token
                whose validated claims are preferred where they overlap.
            config: The provider configuration the tokens were issued under; its
                ``issuer`` and ``client_id`` are what the ID token is validated
                against.

        Returns:
            The identity profile. ``provider`` is namespaced by issuer (see
            :func:`_provider_name`) and ``tenancies`` is always empty.

        Raises:
            ConfigurationError: If ``config`` names no issuer, which leaves an
                ID token's ``iss`` with nothing to be checked against.
            IdentityScopeNotGrantedError: If there is no usable ID token and the
                userinfo endpoint answers 403 ``insufficient_scope`` (RFC 6750).
            IdentityFetchError: If the ID token's claims do not validate or its
                ``sub`` is not a non-empty string, the userinfo request fails or cannot be parsed while there is no
                validated ID token to fall back on, the two documents name
                different subjects, userinfo names no subject beside a
                validated ID token, or neither yields a subject.
        """
        if config.issuer is None:
            msg = "OpenID provider config names no issuer; an ID token's iss could not be validated"
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
                # Userinfo only enriches a subject the validated ID token already
                # gave; the exception class is logged, not its value.
                logger.warning(
                    "OpenID userinfo request failed (%s); identity rests on the ID token alone", type(exc).__name__
                )

        claims_subject = _claim_str(claims, "sub")
        if claims is not None and claims_subject is None:
            # Authlib only requires the claim to be present, so a non-string or
            # empty ``sub`` would otherwise surface as a userinfo mismatch.
            msg = "OpenID ID token has an invalid sub claim"
            raise IdentityFetchError(msg)
        subject = claims_subject or _claim_str(userinfo, "sub")
        if subject is None:
            msg = "OpenID sign-in returned no subject"
            raise IdentityFetchError(msg)
        if claims is not None and userinfo_fetched:
            # Section 5.3.2: the userinfo ``sub`` MUST match the ID token's
            # exactly, and an absent one does not. Without this, a userinfo
            # response naming nobody could still lend its email to the ID
            # token's subject.
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
            # Keyed rather than merged, following ``providers.github``. The two
            # documents carry different weight — one is issuer-asserted, one is
            # whatever the userinfo endpoint chose to return — and a flat merge
            # would leave a caller unable to tell which said what. Claims that
            # exist only on the ID token (``groups``, ``roles``, ``acr``,
            # ``amr``) reach a caller here and nowhere else.
            raw={"id_token": claims or {}, "userinfo": userinfo},
        )

    def _validated_claims(self, id_token: str, access_token: str, issuer: str, client_id: str) -> dict[str, Any] | None:
        """Return the ID token's claims once they check out.

        Validation is :class:`authlib.oidc.core.CodeIDToken`, authlib's
        implementation of the OpenID Connect Core 1.0 section 3.1.3.7 rules for
        an ID token received through the authorization-code flow. It is used
        rather than a hand-rolled equivalent because the rules are more
        conditional than they look: ``azp`` is required only when the effective
        audience differs from this client, ``aud`` may be a string or an array,
        ``at_hash`` is checked against the access token when the token carries
        one, and ``iss``, ``sub``, ``aud``, ``exp`` and ``iat`` are each
        essential. Authlib carries the same validator its own OpenID client
        uses.

        The signature is not checked: these tokens arrive on the
        token-endpoint response over the back-channel, where TLS authenticates
        the issuer (section 3.1.3.7 step 6). What is checked is every claim,
        which is the half that stays the client's job. ``at_hash`` is not part
        of the signature check but is still verified against the access token
        it was minted over, which is the binding OpenID Connect Core 1.0
        section 3.1.3.7 step 8 asks a client to confirm.

        ``None`` when the token is not a parseable JWT, which degrades to
        userinfo rather than failing: a provider that returns something
        unparseable in ``id_token`` has still authenticated somebody, and
        userinfo will say who. A token that parses but whose claims are *wrong*
        is a different matter and raises, because that is a token minted for
        someone else or by someone else.

        Args:
            id_token: The ID token from the token-endpoint response.
            access_token: The access token from the same response, which
                ``at_hash`` — when present — is verified against.
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
        except (JoseError, ValueError, UnicodeDecodeError) as exc:
            # The exception class only, so no token-derived bytes are emitted.
            logger.warning("OpenID ID token dropped, identity falls back to userinfo: %s", type(exc).__name__)
            return None
        if not isinstance(claims, dict):
            logger.warning("OpenID ID token dropped, identity falls back to userinfo: payload was not a JSON object")
            return None
        token = CodeIDToken(
            claims,
            # The token's real header, not ``{}``. ``validate_at_hash`` reads
            # ``header["alg"]`` when the token carries an ``at_hash`` — the
            # access token threaded through below is what makes that path live
            # — so an empty stand-in would raise ``KeyError`` the moment it is
            # exercised, and it is already parsed here anyway.
            signature.headers(),
            # ``aud`` must be declared explicitly. ``CodeIDToken`` derives the
            # ``azp`` rules from ``client_id`` but does *not* compare ``aud``
            # against it on its own, so a token carrying
            # ``aud=<someone-else>, azp=<us>`` is accepted without this option
            # — an audience check that silently is not one.
            {
                "iss": {"values": [issuer], "essential": True},
                "aud": {"values": [client_id], "essential": True},
            },
            {"client_id": client_id, "access_token": access_token},
        )
        try:
            token.validate(leeway=_EXPIRY_LEEWAY_SECONDS)
        except ClaimError as exc:
            raise IdentityFetchError(_claim_error_message(exc)) from exc
        except (JoseError, TypeError, ValueError) as exc:
            # A malformed header or claim shape can escape the validator as a
            # bare ``TypeError``; the contract is ``IdentityFetchError``.
            msg = "OpenID ID token claims did not validate"
            raise IdentityFetchError(msg) from exc
        return claims

    async def _fetch_userinfo(self, userinfo_url: str, access_token: str) -> dict[str, Any]:
        """Fetch the userinfo payload for display fields.

        Args:
            userinfo_url: The userinfo endpoint.
            access_token: The bearer access token for the userinfo request.

        Returns:
            The userinfo payload as a JSON object.

        Raises:
            IdentityScopeNotGrantedError: If the endpoint answers 403
                ``insufficient_scope``.
            IdentityFetchError: If the request fails, its response cannot be
                parsed, or it is not a JSON object.
        """
        transport = self._transport_factory(userinfo_url) if self._transport_factory is not None else None
        try:
            async with httpx.AsyncClient(transport=transport, timeout=_USERINFO_TIMEOUT) as client:
                response = await client.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403 and _INSUFFICIENT_SCOPE.search(
                exc.response.headers.get("www-authenticate", "")
            ):
                raise IdentityScopeNotGrantedError("OpenID userinfo refused the token: insufficient_scope") from exc
            raise IdentityFetchError(f"Failed to fetch OpenID identity: {exc}") from exc
        except (httpx.InvalidURL, httpx.RequestError) as exc:
            # ``InvalidURL`` is not a ``RequestError``; the userinfo URL comes
            # from the discovery document unvalidated, so a malformed one must
            # still surface as the ``IdentityFetchError`` callers expect.
            raise IdentityFetchError(f"Failed to fetch OpenID identity: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityFetchError(f"Failed to parse OpenID identity response: {exc}") from exc
        if not isinstance(payload, dict):
            # A provider registered for a signed userinfo response returns
            # ``application/jwt`` here (section 5.3.2). This library does not
            # verify signatures, so it refuses rather than reading such a
            # response unverified; register the client for JSON instead.
            msg = "OpenID identity response was not a JSON object"
            raise IdentityFetchError(msg)
        return payload


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

    Namespaced by issuer, because a bare ``"oidc"`` would be wrong in a way
    that matters. :meth:`~apron_auth.models.IdentityProfile.identity_key`
    returns ``(provider, subject)`` as the recommended primary key for a user
    table, and a ``sub`` is only unique *within* an issuer (OpenID Connect Core
    1.0, section 2). Two generic connections — say an Okta tenant and a
    Keycloak realm — would otherwise collide on ``("oidc", sub)``, and any
    ``sub`` one issuer can be made to mint becomes a key collision against the
    other. Every other provider in this package is safe with a bare name only
    because its name is one-to-one with an issuer; this one is not.

    Args:
        issuer: The validated issuer identifier.

    Returns:
        The provider string, of the form ``oidc:<issuer>``.
    """
    return f"oidc:{issuer}"


def _email_fields(claims: dict[str, Any] | None, userinfo: dict[str, Any]) -> tuple[str | None, bool | None]:
    """The ``email`` and ``email_verified`` pair, taken from a single document.

    Both fields come from the *same* source — the ID token when it carries an
    ``email``, else userinfo — because they are one assertion, not two.
    Sourcing them independently lets an ID token's address pair with userinfo's
    verification flag, and
    :meth:`~apron_auth.models.IdentityProfile.verified_email` would then return
    an address nothing had vouched for. Every other handler in this package
    reads both from one payload by construction; this one has two payloads and
    has to choose deliberately.

    ``email_verified`` is honored only as a genuine JSON boolean, and reported
    as ``None`` when the chosen document omits it: a bare ``bool()`` would read
    the string ``"false"`` as ``True``, and an unasserted value is not the same
    fact as an asserted ``false``. Callers that must decide on a boolean
    collapse the unasserted case themselves, and toward unverified. An
    ``email_verified`` with no ``email`` beside it asserts nothing and is
    dropped.

    Args:
        claims: The validated ID-token claims, or ``None`` when absent.
        userinfo: The userinfo payload, empty when none was fetched.

    Returns:
        The address and its verification flag, both from one document, or
        ``(None, None)`` when neither carries an address.
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


def _optional_str(value: Any) -> str | None:
    """Return ``value`` when it is a non-empty string, else ``None``.

    Args:
        value: The raw JSON value from the configuration document.

    Returns:
        The string, or ``None`` when absent, empty, or the wrong type.
    """
    return value if isinstance(value, str) and value else None


def _str_list(value: Any) -> list[str]:
    """Return the string entries of a JSON array, or an empty list.

    A non-array, or an array with non-string entries, yields only what is
    usable rather than raising: these are advisory ``*_supported`` lists, and a
    provider malforming one should not fail discovery outright.

    Args:
        value: The raw JSON value from the configuration document.

    Returns:
        The string entries, or ``[]``.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, str)]


def _strict_str_list(document: dict[str, Any], key: str) -> list[str]:
    """Return a security-relevant list member, refusing a malformed one.

    Unlike :func:`_str_list`, a present-but-malformed value is an error: these
    lists gate a refusal (PKCE methods, token-endpoint auth methods), and
    treating ``"plain"`` as "not advertised" would take the permissive branch.

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

    Prefers ``client_secret_post`` among the methods the provider advertises,
    and falls back to it when the provider advertises none, which RFC 8414
    section 2 reads as ``client_secret_basic`` but which providers omit far
    more often than they mean it.

    Args:
        advertised: The methods the provider advertises support for.

    Returns:
        The method to authenticate the token request with.

    Raises:
        ConfigurationError: If the provider advertises only methods this
            library cannot perform. This is a capability mismatch in an
            otherwise-valid configuration document, so it is a configuration
            error rather than a discovery failure.
    """
    if not advertised:
        return TokenEndpointAuthMethod.CLIENT_SECRET_POST
    for method in _CONFIDENTIAL_AUTH_METHODS:
        if method in advertised:
            return method
    msg = "OpenID provider advertises no token-endpoint auth method this library can perform"
    raise ConfigurationError(msg)


def _require_url(value: Any, *, field: str, allow_insecure_http: bool, is_issuer: bool = False) -> str:
    """Require ``value`` to be an absolute URL this module may talk to.

    The one URL rule for the issuer, the document URL and every endpoint: a
    string with a scheme and a host, no fragment, and ``https`` unless
    ``allow_insecure_http`` is set. An issuer additionally has no query and no
    userinfo (OpenID Connect Discovery 1.0, section 4.1).

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
        msg = f"OpenID discovery received a malformed {field}"
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
    if parsed.fragment:
        msg = f"OpenID {field} must not carry a fragment"
        raise OidcDiscoveryError(msg)
    if is_issuer and (parsed.query or "?" in value):
        msg = f"OpenID {field} must not carry a query"
        raise OidcDiscoveryError(msg)
    if is_issuer and (parsed.username is not None or parsed.password is not None or "@" in parsed.netloc):
        msg = f"OpenID {field} must not carry userinfo"
        raise OidcDiscoveryError(msg)
    return value


def _optional_url(document: dict[str, Any], key: str, field: str, allow_insecure_http: bool) -> str | None:
    """Validate an optional endpoint when the document names one.

    Args:
        document: The configuration document.
        key: The document member to read.
        field: What the endpoint is, for errors.
        allow_insecure_http: Passed through to :func:`_require_url`.

    Returns:
        The endpoint, or ``None`` when the document omits it.

    Raises:
        OidcDiscoveryError: If the member is present but not an acceptable URL.
    """
    value = document.get(key)
    if value is None:
        return None
    return _require_url(value, field=field, allow_insecure_http=allow_insecure_http)


async def _fetch_document(url: str, transport_factory: TransportFactory | None) -> dict[str, Any]:
    """Fetch the configuration document at ``url``.

    Redirects are not followed, so the request goes to the URL derived from the
    issuer and nowhere else. ``httpx.InvalidURL`` is caught alongside transport
    failures: it is not a ``RequestError``, so a malformed ``document_url``
    would otherwise escape as an httpx exception rather than the
    ``OidcDiscoveryError`` this module documents.

    Args:
        url: The document URL, already validated.
        transport_factory: Optional factory controlling the outbound connection.

    Returns:
        The document as a JSON object.

    Raises:
        OidcDiscoveryError: If the request fails, the response is not HTTP 200,
            or its body is not a JSON object.
    """
    transport = transport_factory(url) if transport_factory is not None else None
    async with httpx.AsyncClient(
        transport=transport,
        timeout=_DISCOVERY_TIMEOUT,
        follow_redirects=False,
    ) as client:
        try:
            response = await client.get(url)
        except (httpx.InvalidURL, httpx.RequestError) as exc:
            # The exception class, not its value: the URL is in the caller's
            # config and the value adds only the request line.
            msg = f"could not fetch the OpenID provider configuration ({type(exc).__name__})"
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
