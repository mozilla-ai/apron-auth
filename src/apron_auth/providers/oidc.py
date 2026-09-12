"""Generic OpenID Connect provider preset, discovery, and identity handler.

The preset every other module in this package is not: it names no endpoints,
because it has none to name. An OpenID provider publishes its own configuration
document, so :func:`discover` reads the endpoints from the issuer and
:func:`preset` folds them together with a client identity. That covers Keycloak,
Okta, Auth0, Entra ID, Authentik, Zitadel, Dex, Ping, and anything else that
implements OpenID Connect Discovery 1.0, without a module here per product.

**No identity resolver is registered, deliberately.** Every other provider
infers its handler by matching the config's OAuth hosts against a fixed suffix
list (``providers.identity.infer_identity_handler``). A generic connection's
hosts are whatever the operator configured, so a resolver here would either
match nothing or match everything and make inference ambiguous for the presets
that can answer honestly. A caller using this module passes
:class:`OidcIdentityHandler` to :class:`~apron_auth.client.OAuthClient`
explicitly, which is what :func:`identity_handler` builds from the same metadata
the config came from.

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
5.3.2). :attr:`ServerMetadata.jwks_url`
is carried through discovery so a caller that wants front-channel verification
has somewhere to fetch keys from; this library does not fetch it.

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
  (section 3.1.2.1) and PKCE already covers code injection, so omitting it is
  compliant. What blocks all of them alike is that ``extra_params`` is fixed on
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
* **HTTPS is not enforced.** The endpoint URLs a configuration document names
  are carried through exactly as named, so a document that advertises an
  ``http://`` token endpoint is used at that URL. Sending client credentials
  in clear is the operator's choice; this library's contribution is
  documenting it (see :func:`discover`) rather than silently upgrading or
  refusing a clear-text endpoint.
* **RP-Initiated Logout is not wired up**, though
  ``authlib.integrations.base_client`` implements it in ``create_logout_url``
  should this module ever grow it.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
from authlib.oidc.core import CodeIDToken
from authlib.oidc.discovery import get_well_known_url
from joserfc import jws
from joserfc.errors import JoseError
from pydantic import SecretStr

from apron_auth.errors import ConfigurationError, IdentityFetchError, OidcDiscoveryError
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


def discovery_url(issuer: str) -> str:
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
    bare hostname — because appending a well-known suffix to a relative
    string produces a relative URL that no client can fetch. The scheme is
    not restricted to ``https``: keeping an issuer (and its document)
    served in clear is the operator's choice, documented in :func:`discover`.

    Args:
        issuer: The issuer identifier to derive the document URL from.

    Returns:
        The configuration document's URL.

    Raises:
        OidcDiscoveryError: If ``issuer`` is not a parseable absolute URL.
    """
    try:
        parsed = urlparse(issuer)
    except ValueError as exc:
        msg = "OpenID discovery received a malformed issuer"
        raise OidcDiscoveryError(msg) from exc
    if not parsed.scheme or not parsed.netloc:
        msg = "OpenID discovery received an issuer that is not an absolute URL"
        raise OidcDiscoveryError(msg)
    return get_well_known_url(issuer, external=True)


async def discover(
    issuer: str,
    *,
    document_url: str | None = None,
    transport_factory: TransportFactory | None = None,
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
            connection. This is where network policy belongs: no scheme or
            host check is applied here, because whether a given issuer may be
            reached is the deployment's question, not this library's, and a
            check that inspects only the URL string cannot answer it anyway —
            a hostname resolving to an internal address passes any such test.

        The endpoint URLs the document names are carried through exactly as
        named, including their scheme. HTTPS is *not* enforced: a document
        that advertises an ``http://`` token endpoint is used at that URL,
        and a caller that POSTs client credentials there has chosen to send
        them in clear. Whether a deployment may serve an issuer over HTTP is
        the operator's responsibility; this module's only contribution is
        documenting that the credential-bearing endpoints are used
        verbatim, so the decision is an informed one.

    Returns:
        The discovered metadata, carrying the userinfo and JWKS endpoints
        alongside the authorization-code flow's own.

    Raises:
        OidcDiscoveryError: If the issuer is malformed, the document cannot be
            fetched or parsed, it omits an endpoint the flow requires, or it
            names an issuer other than ``issuer``.
    """
    url = document_url or discovery_url(issuer)
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
    if not isinstance(authorize_url, str) or not isinstance(token_url, str):
        msg = "OpenID provider configuration is missing an endpoint"
        raise OidcDiscoveryError(msg)

    userinfo_url = _optional_str(document.get("userinfo_endpoint"))
    jwks_url = _optional_str(document.get("jwks_uri"))
    revocation_url = _optional_str(document.get("revocation_endpoint"))
    registration_url = _optional_str(document.get("registration_endpoint"))

    return ServerMetadata(
        authorize_url=authorize_url,
        token_url=token_url,
        registration_url=registration_url,
        revocation_url=revocation_url,
        scopes_supported=_str_list(document.get("scopes_supported")),
        code_challenge_methods=_str_list(document.get("code_challenge_methods_supported")),
        token_endpoint_auth_methods=_str_list(document.get("token_endpoint_auth_methods_supported")),
        issuer=declared_issuer,
        iss_parameter_supported=document.get("authorization_response_iss_parameter_supported") is True,
        userinfo_url=userinfo_url,
        jwks_url=jwks_url,
    )


def preset(
    client_id: str,
    client_secret: str,
    scopes: list[str],
    metadata: ServerMetadata,
    redirect_uri: str | None = None,
    extra_params: dict[str, str] | None = None,
) -> tuple[ProviderConfig, RevocationHandler | None]:
    """Create a provider configuration from a discovered OpenID provider.

    Takes ``metadata`` where every other preset hardcodes endpoints, so the
    argument order departs from theirs: a generic connection cannot be
    configured without the discovery step, and making it a parameter rather
    than an implicit fetch keeps this function synchronous and keeps the
    network call somewhere a caller can cache, validate, or stub.

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
    PKCE, because one that does not implement it ignores the extra parameters
    as unknown.

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
    client_id: str,
    transport_factory: TransportFactory | None = None,
) -> OidcIdentityHandler:
    """Build the identity handler for a discovered provider.

    The counterpart to the inference every other provider gets for free from
    ``providers.identity``, which this module cannot participate in; see the
    module docstring.

    Args:
        metadata: The provider's discovered metadata, from :func:`discover`.
        client_id: The client identifier an ID token's ``aud`` must name. This
            must be the same value passed to :func:`preset`; a mismatch rejects
            every ID token the provider issues.
        transport_factory: Optional factory controlling the outbound connection
            for the userinfo request, matching the one :func:`discover` accepts.

    Returns:
        The identity handler for this provider.

    Raises:
        OidcDiscoveryError: If the metadata names no issuer, which leaves an ID
            token's ``iss`` with nothing to be checked against.
    """
    if metadata.issuer is None:
        msg = "OpenID provider metadata names no issuer; an ID token's iss could not be validated"
        raise OidcDiscoveryError(msg)
    return OidcIdentityHandler(
        userinfo_url=metadata.userinfo_url,
        issuer=metadata.issuer,
        client_id=client_id,
        transport_factory=transport_factory,
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

    A userinfo response whose ``sub`` names a different subject than the ID
    token is refused outright rather than reconciled (OpenID Connect Core 1.0,
    section 5.3.2): the two documents disagreeing about who signed in is not a
    field to prefer between.
    """

    def __init__(
        self,
        *,
        userinfo_url: str | None,
        issuer: str,
        client_id: str,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        """Configure which provider this establishes identities against.

        Args:
            userinfo_url: The provider's userinfo endpoint, or ``None`` when it
                advertises none and identity rests on the ID token alone.
            issuer: The issuer an ID token's ``iss`` must name. Required rather
                than optional: OpenID Connect Core 1.0 section 3.1.3.7 step 2
                makes the comparison a MUST, and an issuer-less handler would
                silently skip it.
            client_id: The client identifier an ID token's ``aud`` must name.
            transport_factory: Optional factory controlling the outbound
                connection for the userinfo request.
        """
        self._userinfo_url = userinfo_url
        self._issuer = issuer
        self._client_id = client_id
        self._transport_factory = transport_factory

    async def fetch_identity(self, material: IdentityMaterial, config: ProviderConfig) -> IdentityProfile:
        """Fetch normalized identity fields for a generic OpenID sign-in.

        Args:
            material: The token material — the access token, and the ID token
                whose validated claims are preferred where they overlap.
            config: The provider configuration the tokens were issued under.
                Unused: everything this needs was fixed at construction, from
                the metadata the config was itself derived from.

        Returns:
            The identity profile. ``provider`` is namespaced by issuer (see
            :func:`_provider_name`) and ``tenancies`` is always empty.

        Raises:
            IdentityFetchError: If the ID token's claims do not validate, the
                userinfo request fails or cannot be parsed, the two documents
                name different subjects, or neither yields a subject.
        """
        del config
        claims = self._validated_claims(material.id_token, material.access_token) if material.id_token else None
        userinfo = await self._fetch_userinfo(material.access_token) if self._userinfo_url else {}

        claims_subject = _claim_str(claims, "sub")
        subject = claims_subject or _claim_str(userinfo, "sub")
        if subject is None:
            msg = "OpenID sign-in returned no subject"
            raise IdentityFetchError(msg)
        userinfo_subject = _claim_str(userinfo, "sub")
        if claims is not None and userinfo_subject is not None and userinfo_subject != claims_subject:
            msg = "OpenID userinfo response names a different subject than the ID token"
            raise IdentityFetchError(msg)

        email, email_verified = _email_fields(claims, userinfo)
        return IdentityProfile(
            provider=_provider_name(self._issuer),
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

    def _validated_claims(self, id_token: str, access_token: str) -> dict[str, Any] | None:
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

        Returns:
            The validated claims, or ``None`` when the token is unparseable.

        Raises:
            IdentityFetchError: If any claim does not validate.
        """
        try:
            signature = jws.extract_compact(id_token.encode())
            claims = json.loads(signature.payload)
        except (JoseError, ValueError, UnicodeDecodeError) as exc:
            # The exception class is logged, never its value, so no
            # token-derived bytes are emitted.
            logger.debug("OpenID id token claim extraction failed: %s", type(exc).__name__)
            return None
        if not isinstance(claims, dict):
            logger.debug("OpenID id token payload was not a JSON object")
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
                "iss": {"values": [self._issuer], "essential": True},
                "aud": {"values": [self._client_id], "essential": True},
            },
            {"client_id": self._client_id, "access_token": access_token},
        )
        try:
            token.validate(leeway=_EXPIRY_LEEWAY_SECONDS)
        except JoseError as exc:
            # The joserfc message names the offending claim (e.g. "Missing
            # claim: 'azp'"), which is the whole diagnostic; the token's own
            # values are never interpolated.
            raise IdentityFetchError(f"OpenID ID token claims did not validate: {exc}") from exc
        return claims

    async def _fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch the userinfo payload for display fields.

        Args:
            access_token: The bearer access token for the userinfo request.

        Returns:
            The userinfo payload as a JSON object.

        Raises:
            IdentityFetchError: If the request fails, its response cannot be
                parsed, or it is not a JSON object.
        """
        assert self._userinfo_url is not None, "caller checks for a userinfo endpoint before calling"
        transport = self._transport_factory(self._userinfo_url) if self._transport_factory is not None else None
        try:
            async with httpx.AsyncClient(transport=transport, timeout=_USERINFO_TIMEOUT) as client:
                response = await client.get(
                    self._userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
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
                location = response.headers.get("location")
                target = f" to {location!r}" if location else ""
                # Redirects are deliberately not followed, so this surfaces the
                # reason a live provider fronted by a CDN or load balancer
                # failed. The target is the actionable part: pass it as
                # ``document_url`` when it is the canonical document URL.
                logger.warning(
                    "OpenID provider configuration returned HTTP %s%s; redirects are not followed, "
                    "so the fetch failed — pass the redirect target as document_url if it is canonical",
                    response.status_code,
                    target,
                )
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
