"""Generic MCP-server OAuth support: discover metadata, build a ProviderConfig.

Discovers a remote MCP server's OAuth endpoints via RFC 9728 (Protected
Resource Metadata) and RFC 8414 (Authorization Server Metadata), then folds
them together with a client identity into a
:class:`~apron_auth.models.ProviderConfig` for the existing
:class:`~apron_auth.client.OAuthClient`.

Discovery fetches URLs taken from server-supplied metadata. The baseline
requires HTTPS and rejects non-public IP-literal hosts, and an optional
``url_validator`` may reject URLs; because these do not stop DNS-based
rebinding, a caller handling untrusted input should supply a
``transport_factory`` whose transport pins DNS to validated addresses. This
module is stateless and stores no credentials.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import SecretStr

from apron_auth.errors import McpDiscoveryError, McpRegistrationError, OAuthError
from apron_auth.models import (
    ApplicationType,
    ClientRegistration,
    ProviderConfig,
    ServerMetadata,
    TokenEndpointAuthMethod,
)
from apron_auth.protocols import TransportFactory

UrlValidator = Callable[[str], None]

logger = logging.getLogger(__name__)

_DISCOVERY_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_WELL_KNOWN_PRM = "/.well-known/oauth-protected-resource"
_WELL_KNOWN_ASM = "/.well-known/oauth-authorization-server"
_WELL_KNOWN_OIDC = "/.well-known/openid-configuration"

# Token-endpoint auth methods this library can perform for a confidential
# client, in the order it prefers them. authlib drives all of these.
_CONFIDENTIAL_AUTH_METHODS = (
    TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
)


async def discover(
    server_url: str,
    *,
    resource_metadata_url: str | None = None,
    url_validator: UrlValidator | None = None,
    transport_factory: TransportFactory | None = None,
) -> ServerMetadata:
    """Discover a remote MCP server's OAuth metadata.

    Fetches the RFC 9728 protected-resource metadata (trying the
    ``resource_metadata_url`` hint, then well-known locations), reads its first
    authorization server, and fetches that server's RFC 8414 metadata (with an
    OIDC fallback). The HTTPS requirement and non-public-IP-literal block are
    defense-in-depth; they do not stop a hostname that resolves to an internal
    address, so untrusted ``server_url`` values need a ``transport_factory``
    that pins DNS to validated addresses.

    Args:
        server_url: Base URL of the MCP server.
        resource_metadata_url: Optional hint from a ``WWW-Authenticate``
            challenge, tried before the well-known locations.
        url_validator: Optional policy invoked on each URL before it is
            requested; raising rejects the URL and fails discovery.
        transport_factory: Optional factory returning an httpx transport for a
            URL, letting the caller control the outbound connection (e.g. pin
            DNS to validated public IPs to prevent SSRF via rebinding).

    Returns:
        The discovered metadata.

    Raises:
        McpDiscoveryError: If a URL is rejected, no metadata document can be
            fetched, or a required field is absent.
    """
    _validate_url(server_url, url_validator)

    resource_meta = await _fetch_first_metadata(
        _prm_candidate_urls(resource_metadata_url, server_url),
        url_validator,
        transport_factory,
        "protected resource metadata",
    )
    auth_servers = resource_meta.get("authorization_servers")
    auth_server = None
    if isinstance(auth_servers, list):
        auth_server = next((item for item in auth_servers if isinstance(item, str) and item), None)
    if not auth_server:
        msg = "protected resource metadata declares no authorization server"
        raise McpDiscoveryError(msg)
    _validate_url(auth_server, url_validator)

    server_meta = await _fetch_first_metadata(
        _asm_candidate_urls(auth_server),
        url_validator,
        transport_factory,
        "authorization server metadata",
    )
    authorize_url = server_meta.get("authorization_endpoint")
    token_url = server_meta.get("token_endpoint")
    if not isinstance(authorize_url, str) or not isinstance(token_url, str):
        msg = "authorization server metadata is missing an endpoint"
        raise McpDiscoveryError(msg)

    registration = server_meta.get("registration_endpoint")
    revocation = server_meta.get("revocation_endpoint")
    registration_url = registration if isinstance(registration, str) else None
    revocation_url = revocation if isinstance(revocation, str) else None
    for url in (authorize_url, token_url, registration_url, revocation_url):
        if url is not None:
            _validate_url(url, url_validator)

    issuer = server_meta.get("issuer")
    return ServerMetadata(
        authorize_url=authorize_url,
        token_url=token_url,
        registration_url=registration_url,
        revocation_url=revocation_url,
        scopes_supported=_str_list(server_meta.get("scopes_supported")),
        code_challenge_methods=_str_list(server_meta.get("code_challenge_methods_supported")),
        token_endpoint_auth_methods=_str_list(server_meta.get("token_endpoint_auth_methods_supported")),
        issuer=issuer if isinstance(issuer, str) else None,
        iss_parameter_supported=server_meta.get("authorization_response_iss_parameter_supported") is True,
    )


def to_provider_config(
    metadata: ServerMetadata,
    *,
    client_id: str,
    client_secret: SecretStr | str | None = None,
    registered_auth_method: str | None = None,
    scopes: Sequence[str] = (),
    redirect_uri: str | None = None,
) -> ProviderConfig:
    """Fold discovered metadata and a client identity into a ProviderConfig.

    PKCE is enabled unless the server advertises code-challenge methods that
    exclude S256; because :class:`~apron_auth.client.OAuthClient` issues only
    S256 challenges, PKCE is disabled rather than downgraded to ``plain``. The
    token-endpoint auth method is taken from ``registered_auth_method`` when
    given — the value is authoritative for this specific client and may differ
    from what the server advertises server-wide. Absent it, a confidential
    client's method is chosen from the methods the server advertises (preferring
    ``client_secret_post``) and a secretless public client uses ``none``. The
    discovered issuer and its ``iss``-parameter support carry onto the config so
    the code exchange can validate the authorization-response ``iss`` (RFC 9207).

    Args:
        metadata: Metadata from :func:`discover`.
        client_id: Client identifier, pre-registered or minted via DCR.
        client_secret: Secret for a confidential client; omit for a public one.
        registered_auth_method: The token-endpoint auth method the server
            registered for this client (RFC 7591), when known; overrides the
            derivation from the advertised set. Omit when unknown.
        scopes: Scopes to request.
        redirect_uri: Redirect URI for the authorization flow.

    Returns:
        A provider configuration for :class:`~apron_auth.client.OAuthClient`.

    Raises:
        McpDiscoveryError: If the registered method is one this library cannot
            perform, or the server advertises only such methods for a
            confidential client.
    """
    secret = SecretStr(client_secret) if isinstance(client_secret, str) else client_secret
    methods = metadata.code_challenge_methods
    # Default PKCE on when the server advertises no code-challenge methods. RFC
    # 8414 reads an omitted list as "no PKCE", but the MCP spec requires clients
    # to use PKCE (OAuth 2.1 section 7.5.2) and servers to implement OAuth 2.1,
    # so a conformant MCP server supports it even without advertising, and one
    # that genuinely does not ignores the challenge as an unknown parameter.
    # When methods are advertised, honor them: disable if S256 is absent, since
    # OAuthClient issues only S256 challenges.
    use_pkce = "S256" in methods if methods else True
    auth_method = _select_auth_method(secret, metadata.token_endpoint_auth_methods, registered_auth_method)
    return ProviderConfig(
        client_id=client_id,
        client_secret=secret,
        authorize_url=metadata.authorize_url,
        token_url=metadata.token_url,
        revocation_url=metadata.revocation_url,
        redirect_uri=redirect_uri,
        scopes=list(scopes),
        use_pkce=use_pkce,
        token_endpoint_auth_method=auth_method,
        issuer=metadata.issuer,
        require_iss=metadata.iss_parameter_supported,
    )


async def register_client(
    registration_url: str,
    redirect_uri: str,
    *,
    client_name: str = "apron-auth",
    application_type: str | None = None,
    url_validator: UrlValidator | None = None,
    transport_factory: TransportFactory | None = None,
) -> ClientRegistration:
    """Dynamically register an OAuth client (RFC 7591) and return its credentials.

    POSTs a registration request to ``registration_url`` (an authorization
    server's registration endpoint) and returns the issued ``client_id`` plus,
    for a confidential client, a ``client_secret``. Any
    ``token_endpoint_auth_method`` the response states is captured too — it is
    authoritative for this client and may differ from the requested method. The
    URL is validated (HTTPS, non-public host, ``url_validator``) and the request
    goes through ``transport_factory`` when supplied. An error never echoes the
    response body, which carries the issued secret.

    Args:
        registration_url: The authorization server's registration endpoint.
        redirect_uri: Redirect URI to register for the authorization flow.
        client_name: Human-readable client name sent in the request.
        application_type: The application_type to register
            (``ApplicationType.WEB`` or ``ApplicationType.NATIVE``). When
            omitted, ``native`` is inferred from a loopback ``redirect_uri``
            and otherwise left unset. Registering ``native`` lets servers that
            gate ``localhost`` redirects on it accept the registration.
        url_validator: Optional policy invoked on the URL before the request.
        transport_factory: Optional factory controlling the outbound connection.

    Returns:
        The issued client registration. Its credentials are bound to the
        authorization server that minted them; see
        :class:`~apron_auth.models.ClientRegistration` for the caller's
        persistence obligation.

    Raises:
        ValueError: If ``application_type`` is neither ``web`` nor ``native``.
        McpRegistrationError: If the URL is rejected, the endpoint returns a
            non-success status, or the response lacks a usable ``client_id``.
    """
    _validate_url(registration_url, url_validator, McpRegistrationError)
    if application_type not in (None, ApplicationType.WEB, ApplicationType.NATIVE):
        msg = "application_type must be 'web' or 'native'"
        raise ValueError(msg)
    if application_type is None:
        application_type = _infer_application_type(redirect_uri)
    payload = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    }
    if application_type is not None:
        payload["application_type"] = application_type
    async with _discovery_client(registration_url, transport_factory) as client:
        try:
            response = await client.post(registration_url, json=payload)
        except httpx.RequestError as exc:
            msg = f"client registration request failed: {type(exc).__name__}"
            raise McpRegistrationError(msg) from exc
        if response.status_code not in (200, 201):
            msg = f"client registration failed: HTTP {response.status_code}"
            raise McpRegistrationError(msg)
        try:
            data = response.json()
        except ValueError:
            msg = "client registration returned a non-JSON response"
            raise McpRegistrationError(msg) from None

    if not isinstance(data, dict):
        msg = "client registration returned an unexpected response"
        raise McpRegistrationError(msg)
    client_id = data.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        msg = "client registration response is missing client_id"
        raise McpRegistrationError(msg)
    client_secret = data.get("client_secret")
    auth_method = data.get("token_endpoint_auth_method")
    return ClientRegistration(
        client_id=client_id,
        client_secret=SecretStr(client_secret) if isinstance(client_secret, str) else None,
        token_endpoint_auth_method=auth_method if isinstance(auth_method, str) else None,
    )


def _str_list(value: Any) -> list[str]:
    """Return the string items of value when it is a list, else an empty list."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _select_auth_method(secret: SecretStr | None, advertised: list[str], registered: str | None = None) -> str:
    """Choose the token-endpoint authentication method for a discovered server.

    A ``registered`` method is authoritative and takes precedence: it is the
    method the server assigned this specific client (RFC 7591) and may differ
    from the server-wide advertised set, so when present it is honored (or
    raises if this library cannot perform it) and the advertised set is not
    consulted.

    Otherwise the method is derived. A secretless client is public and uses
    ``none``, unless the server publishes an explicit method list that omits
    ``none`` — then it accepts no public client and this raises. A confidential
    client uses the first method in :data:`_CONFIDENTIAL_AUTH_METHODS` the server
    advertises; a server advertising only methods this library cannot perform is
    unusable, so this raises rather than yielding a config doomed to fail at
    token exchange. When the server advertises nothing, this defaults to
    ``client_secret_basic`` — RFC 8414's stated default, and the one scheme
    RFC 6749 requires every authorization server to support.

    Args:
        secret: The client secret, or None for a public client.
        advertised: The server's advertised token-endpoint auth methods.
        registered: The method the server registered for this client, or None
            when unknown. Any non-None value — including an empty string — is
            treated as an asserted method and validated, not silently ignored.

    Returns:
        A token-endpoint authentication method.

    Raises:
        McpDiscoveryError: If the registered method is one this library cannot
            perform, or the server advertises an explicit method list the client
            cannot satisfy — omitting ``none`` for a public client, or offering
            only methods this library cannot perform for a confidential client.
    """
    if registered is not None:
        return _honor_registered_auth_method(registered, secret)
    if secret is None:
        # A public client authenticates with no credentials ("none"). An empty
        # advertised list means the server published nothing, which we do not
        # treat as a rejection. But an explicit list that omits "none" means the
        # token endpoint requires client authentication, so a public client
        # cannot use it — fail fast rather than emit a config that would be
        # rejected at token exchange.
        if advertised and TokenEndpointAuthMethod.NONE not in advertised:
            msg = "MCP server does not accept a public client at its token endpoint"
            raise McpDiscoveryError(msg)
        return TokenEndpointAuthMethod.NONE
    if not advertised:
        return TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
    for method in _CONFIDENTIAL_AUTH_METHODS:
        if method in advertised:
            return method
    msg = "MCP server requires an unsupported client authentication method"
    raise McpDiscoveryError(msg)


def _honor_registered_auth_method(registered: str, secret: SecretStr | None) -> str:
    """Return the method the server registered for this client, if performable.

    The registered method (RFC 7591) is authoritative for the client, so this
    honors ``none`` for a public client and the confidential methods in
    :data:`_CONFIDENTIAL_AUTH_METHODS`. It raises rather than yielding an
    internally inconsistent config when the method and the secret disagree — a
    confidential method with no secret to send, or ``none`` paired with a secret
    (a public client must carry none, and a lingering secret would be attached
    to requests that should present no client authentication) — and when the
    method is one this library cannot perform.

    Args:
        registered: The method the server registered for this client.
        secret: The client secret, or None for a public client.

    Returns:
        The registered token-endpoint authentication method.

    Raises:
        McpDiscoveryError: If the method disagrees with the secret's presence, or
            this library cannot perform it.
    """
    if registered == TokenEndpointAuthMethod.NONE:
        if secret is not None:
            msg = "MCP server registered a public client (none) but issued a client secret"
            raise McpDiscoveryError(msg)
        return TokenEndpointAuthMethod.NONE
    if registered in _CONFIDENTIAL_AUTH_METHODS:
        if secret is None:
            msg = "MCP server registered a confidential auth method but issued no client secret"
            raise McpDiscoveryError(msg)
        return registered
    msg = "MCP server registered an unsupported client authentication method"
    raise McpDiscoveryError(msg)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return host as an IP address, accepting legacy numeric IPv4 forms, else None.

    ``ipaddress.ip_address`` accepts only canonical dotted-quad and IPv6 text, so
    decimal (``2130706433``), hex (``0x7f000001``), octal, and short-form
    (``127.1``) literals slip through it as "hostnames" even though a resolver
    dials them as addresses. ``socket.inet_aton`` canonicalizes those IPv4 forms
    so they cannot bypass a host check; genuine hostnames fail it and return None.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return ipaddress.ip_address(packed)


def _is_blocked_host(host: str) -> bool:
    """Return whether host is empty, localhost, or a non-public IP address."""
    if not host or host == "localhost" or host.endswith(".localhost"):
        return True
    address = _parse_ip(host)
    if address is None:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _infer_application_type(redirect_uri: str) -> str | None:
    """Return ``native`` for a loopback redirect URI, else ``None``.

    A loopback host (``localhost`` or a loopback IP literal) is the RFC 8252
    signature of a native or CLI client. Any other redirect leaves the value
    unset so the registration request is byte-identical to one that never
    considered it.
    """
    try:
        host = urlparse(redirect_uri).hostname or ""
    except ValueError:
        return None
    if host == "localhost" or host.endswith(".localhost"):
        return ApplicationType.NATIVE
    address = _parse_ip(host)
    if address is not None and address.is_loopback:
        return ApplicationType.NATIVE
    return None


def _validate_url(
    url: str,
    url_validator: UrlValidator | None,
    error_cls: type[OAuthError] = McpDiscoveryError,
) -> None:
    """Validate an MCP OAuth URL before it is requested.

    Raises ``error_cls`` when the URL is malformed, not HTTPS, or targets a
    non-public host. An ``OAuthError`` from ``url_validator`` propagates
    unchanged; any other validator exception is wrapped in ``error_cls``.
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise error_cls("MCP OAuth received a malformed URL") from exc
    if parsed.scheme != "https":
        msg = "MCP OAuth requires HTTPS URLs"
        raise error_cls(msg)
    if _is_blocked_host(parsed.hostname or ""):
        msg = "MCP OAuth blocked a non-public host"
        raise error_cls(msg)
    if url_validator is None:
        return
    try:
        url_validator(url)
    except OAuthError:
        raise
    except Exception as exc:
        # Any rejection from the caller's validator fails the operation.
        raise error_cls(str(exc)) from exc


def _prm_candidate_urls(resource_metadata_url: str | None, server_url: str) -> list[str]:
    """Return the ordered RFC 9728 protected-resource-metadata URLs to try."""
    urls: list[str] = []
    if resource_metadata_url:
        urls.append(resource_metadata_url)
    parsed = urlparse(server_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        urls.append(urljoin(base, f"{_WELL_KNOWN_PRM}{parsed.path}"))
    urls.append(urljoin(base, _WELL_KNOWN_PRM))
    return urls


def _asm_candidate_urls(auth_server: str) -> list[str]:
    """Return the ordered RFC 8414 metadata URLs to try, with OIDC fallback."""
    parsed = urlparse(auth_server)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    if path:
        return [
            urljoin(base, f"{_WELL_KNOWN_ASM}{path}"),
            urljoin(base, f"{_WELL_KNOWN_OIDC}{path}"),
            urljoin(base, f"{path}{_WELL_KNOWN_OIDC}"),
        ]
    return [urljoin(base, _WELL_KNOWN_ASM), urljoin(base, _WELL_KNOWN_OIDC)]


def _discovery_client(url: str, transport_factory: TransportFactory | None) -> httpx.AsyncClient:
    """Build the httpx client for a discovery or registration fetch.

    Routes the connection through ``transport_factory`` when supplied and
    disables redirect-following, so a validated URL cannot be bounced to an
    unvalidated host mid-request. ``url`` selects the transport; the returned
    client is not otherwise bound to it.
    """
    transport = transport_factory(url) if transport_factory is not None else None
    return httpx.AsyncClient(transport=transport, timeout=_DISCOVERY_TIMEOUT, follow_redirects=False)


async def _fetch_first_metadata(
    candidate_urls: Sequence[str],
    url_validator: UrlValidator | None,
    transport_factory: TransportFactory | None,
    what: str,
) -> dict[str, Any]:
    """Fetch and return the first candidate URL that yields a JSON object.

    Tries each URL in order through a per-URL client from ``transport_factory``,
    skipping request errors, non-200 responses, and non-object bodies. Each skip
    is logged at debug with a non-sensitive reason. Raises McpDiscoveryError
    describing ``what`` when no candidate succeeds.
    """
    for url in candidate_urls:
        _validate_url(url, url_validator)
        async with _discovery_client(url, transport_factory) as client:
            try:
                response = await client.get(url)
            except httpx.RequestError as exc:
                logger.debug("MCP discovery: %s request failed (%s)", what, type(exc).__name__)
                continue
            if response.status_code != 200:
                logger.debug("MCP discovery: %s returned HTTP %d", what, response.status_code)
                continue
            try:
                payload = response.json()
            except ValueError:
                logger.debug("MCP discovery: %s returned a non-JSON body", what)
                continue
            if isinstance(payload, dict):
                return payload
            logger.debug("MCP discovery: %s returned a non-object JSON body", what)
    msg = f"could not fetch {what}"
    raise McpDiscoveryError(msg)
