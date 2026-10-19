"""Generic Model Context Protocol (MCP) server OAuth support: discover metadata, build a ProviderConfig.

This module discovers a remote MCP server's OAuth endpoints from its RFC 9728 and RFC 8414 metadata.
It folds them together with client credentials into a :class:`~apron_auth.models.ProviderConfig`.
That config infers no identity handler.
An authorization server's host does not decide which identity contract applies to its tokens.
This module is stateless and stores no credentials.

Discovery fetches URLs taken from server-supplied metadata.
It requires HTTPS, refuses userinfo, blocks the name ``localhost`` and names under it, blocks IP-literal
hosts that are not globally reachable, and applies an optional ``url_validator`` to every URL.

NOTE: These checks do not stop DNS rebinding.
A caller handling untrusted input should supply a ``transport_factory`` whose transport pins DNS to validated addresses.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from collections.abc import Callable, Sequence
from typing import Any, assert_never
from urllib.parse import ParseResult, urljoin, urlparse

import httpx
from pydantic import SecretStr

from apron_auth._discovery import (
    CONFIDENTIAL_AUTH_METHODS,
    IssuerNotDeclaredError,
    IssuerRefusalReason,
    discovery_client,
    require_declared_issuer,
    str_list,
)
from apron_auth._http_errors import http_failure, status_failure
from apron_auth._json_body import decode_json_body
from apron_auth.errors import ConfigurationError, FailureKind, McpDiscoveryError, McpRegistrationError, OAuthError
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

# The well-known paths of the discovery documents: authorization server (RFC 8414),
# OpenID provider (OpenID Connect Discovery 1.0) and protected resource (RFC 9728).
_WELL_KNOWN_ASM = "/.well-known/oauth-authorization-server"
_WELL_KNOWN_OIDC = "/.well-known/openid-configuration"
_WELL_KNOWN_PRM = "/.well-known/oauth-protected-resource"


async def discover(
    server_url: str,
    *,
    resource_metadata_url: str | None = None,
    url_validator: UrlValidator | None = None,
    transport_factory: TransportFactory | None = None,
) -> ServerMetadata:
    """Discover a remote MCP server's OAuth metadata.

    Fetches the RFC 9728 protected-resource metadata (trying the
    ``resource_metadata_url`` hint, then well-known locations), reads its
    resource identifier and first authorization server, and fetches that
    server's RFC 8414 metadata (with an OIDC fallback). The HTTPS requirement
    and the block on ``localhost`` names and on IP literals that are not
    globally reachable are defense-in-depth; they do not stop any other
    hostname that resolves to an internal address, so untrusted ``server_url``
    values need a ``transport_factory`` that pins DNS to validated addresses.

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
        ConfigurationError: If a URL the caller passed is rejected: ``server_url``,
            the ``resource_metadata_url`` hint, or a protected-resource metadata
            URL derived from ``server_url``.
        McpDiscoveryError: If a URL the metadata declares is rejected, no metadata
            document can be fetched, a required field is absent, or the
            authorization server metadata does not declare the server it was
            fetched from as its issuer. The first document fetched is
            authoritative, so a mismatched issuer ends discovery rather than
            trying the next candidate URL.
    """
    _validate_url(server_url, url_validator, caller_supplied=True)

    resource_meta = await _fetch_first_metadata(
        _prm_candidate_urls(resource_metadata_url, server_url),
        url_validator,
        transport_factory,
        "protected resource metadata",
        caller_supplied=True,
    )
    auth_servers = resource_meta.get("authorization_servers")
    auth_server = None
    if isinstance(auth_servers, list):
        auth_server = next((item for item in auth_servers if isinstance(item, str) and item), None)
    if not auth_server:
        msg = "protected resource metadata declares no authorization server"
        raise McpDiscoveryError(msg, kind=FailureKind.REFUSED)
    _validate_url(auth_server, url_validator, caller_supplied=False)
    # RFC 8414 section 2: an issuer identifier has no query or fragment, and the metadata URL would drop them.
    # The delimiters are checked, so an empty query or fragment counts.
    if "?" in auth_server or "#" in auth_server:
        msg = "protected resource metadata declares an authorization server with a query or a fragment"
        raise McpDiscoveryError(msg, kind=FailureKind.REFUSED)

    server_meta = await _fetch_first_metadata(
        _asm_candidate_urls(auth_server),
        url_validator,
        transport_factory,
        "authorization server metadata",
        caller_supplied=False,
    )
    try:
        require_declared_issuer(server_meta, auth_server)
    except IssuerNotDeclaredError as exc:
        match exc.reason:
            case IssuerRefusalReason.ABSENT:
                msg = "authorization server metadata declares no issuer"
            case IssuerRefusalReason.MISMATCHED:
                msg = "authorization server metadata declares a different issuer than the one it was fetched for"
            case _:
                assert_never(exc.reason)
        raise McpDiscoveryError(msg, kind=FailureKind.REFUSED) from exc

    authorize_url = server_meta.get("authorization_endpoint")
    token_url = server_meta.get("token_endpoint")
    if not isinstance(authorize_url, str) or not isinstance(token_url, str):
        msg = "authorization server metadata is missing an endpoint"
        raise McpDiscoveryError(msg, kind=FailureKind.REFUSED)

    registration = server_meta.get("registration_endpoint")
    revocation = server_meta.get("revocation_endpoint")
    registration_url = registration if isinstance(registration, str) else None
    revocation_url = revocation if isinstance(revocation, str) else None
    for url in (authorize_url, token_url, registration_url, revocation_url):
        if url is not None:
            _validate_url(url, url_validator, caller_supplied=False)

    resource = resource_meta.get("resource")
    return ServerMetadata(
        authorize_url=authorize_url,
        token_url=token_url,
        registration_url=registration_url,
        revocation_url=revocation_url,
        scopes_supported=str_list(server_meta.get("scopes_supported")),
        code_challenge_methods=str_list(server_meta.get("code_challenge_methods_supported")),
        token_endpoint_auth_methods=str_list(server_meta.get("token_endpoint_auth_methods_supported")),
        issuer=auth_server,
        iss_parameter_supported=server_meta.get("authorization_response_iss_parameter_supported") is True,
        supports_cimd=server_meta.get("client_id_metadata_document_supported") is True,
        resource=resource if isinstance(resource, str) else None,
    )


def to_provider_config(
    metadata: ServerMetadata,
    *,
    client_id: str,
    client_secret: SecretStr | str | None = None,
    registered_auth_method: str | None = None,
    scopes: Sequence[str] = (),
    redirect_uri: str | None = None,
    resource: str | None = None,
) -> ProviderConfig:
    """Fold discovered metadata and client credentials into a ProviderConfig that infers no identity handler.

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
    The RFC 8707 resource indicator defaults to the discovered protected-resource
    identifier and can be overridden by ``resource``.

    The returned config disallows identity handler inference, and no parameter re-enables it.
    An authorization server's host does not decide which identity contract applies to its tokens.

    NOTE: Callers must supply an explicit identity handler to fetch identity with the returned config.
    They should choose a built-in handler only when that provider's API accepts this server's tokens.

    Args:
        metadata: Metadata from :func:`discover`.
        client_id: Client identifier, pre-registered or minted via DCR.
        client_secret: Secret for a confidential client; omit for a public one.
        registered_auth_method: The token-endpoint auth method the server
            registered for this client (RFC 7591), when known; overrides the
            derivation from the advertised set. Omit when unknown.
        scopes: Scopes to request.
        redirect_uri: Redirect URI for the authorization flow.
        resource: RFC 8707 resource indicator to audience-bind issued tokens to,
            overriding the discovered :attr:`ServerMetadata.resource`. ``None``
            (the default) selects the discovered identifier rather than clearing
            it — a discovered resource cannot be suppressed here. The resulting
            config carries no resource indicator only when ``resource`` is
            ``None`` and none was discovered.

    Returns:
        A provider configuration for :class:`~apron_auth.client.OAuthClient`.

    Raises:
        McpDiscoveryError: If the registered method is one this library cannot
            perform, or the server advertises only such methods for a
            confidential client.
        ValidationError: If the effective ``resource`` — supplied or discovered —
            is not a valid absolute URI without a fragment.
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
        resource=resource if resource is not None else metadata.resource,
        allow_identity_inference=False,
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
    URL is validated (HTTPS, no userinfo, host not blocked as non-public, ``url_validator``) and the request
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
        ConfigurationError: If ``registration_url`` is rejected.
        McpRegistrationError: If the endpoint returns a non-success status, or the
            response lacks a usable ``client_id``.
        ValueError: If ``application_type`` is neither ``web`` nor ``native``.
    """
    _validate_url(registration_url, url_validator, caller_supplied=True)
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
    async with discovery_client(registration_url, transport_factory) as client:
        try:
            response = await client.post(registration_url, json=payload)
        except httpx.InvalidURL as exc:
            # The client refuses a URL it cannot send, so no request was made and the argument is at fault.
            msg = "MCP OAuth received a malformed URL"
            raise ConfigurationError(msg, kind=FailureKind.CONFIGURATION) from exc
        except httpx.RequestError as exc:
            transport = http_failure(exc)
            msg = f"client registration request failed: {transport.description}"
            raise McpRegistrationError(msg, kind=transport.kind) from exc
        if response.status_code not in (200, 201):
            status = status_failure(response.status_code)
            msg = f"client registration failed: {status.description}"
            raise McpRegistrationError(msg, kind=status.kind)
        try:
            data = decode_json_body(response)
        except ValueError:
            data = None
            failure = "client registration returned a non-JSON response"
        else:
            failure = None
    # NOTE: This raise stays outside the except block, so the error carries no context.
    if failure is not None:
        raise McpRegistrationError(failure, kind=FailureKind.REFUSED)
    if not isinstance(data, dict):
        msg = "client registration returned an unexpected response"
        raise McpRegistrationError(msg, kind=FailureKind.REFUSED)
    client_id = data.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        msg = "client registration response is missing client_id"
        raise McpRegistrationError(msg, kind=FailureKind.REFUSED)
    client_secret = data.get("client_secret")
    auth_method = data.get("token_endpoint_auth_method")
    return ClientRegistration(
        client_id=client_id,
        client_secret=SecretStr(client_secret) if isinstance(client_secret, str) else None,
        token_endpoint_auth_method=auth_method if isinstance(auth_method, str) else None,
    )


def cimd_client_id(url: str) -> str:
    """Validate an HTTPS URL as a Client ID Metadata Document (CIMD) client identifier.

    A CIMD client is identified by an HTTPS URL to a metadata document the client
    hosts, and that URL is sent verbatim as the ``client_id`` in the authorization
    and token requests. This enforces the client-identifier URL rules this library
    can check locally and returns the URL for use as a ``client_id``: an ``https``
    scheme, a valid port, a path component naming the document, and none of the
    components the specification forbids — userinfo, a fragment, or a ``.`` or
    ``..`` path segment. A query string is only discouraged, not forbidden, so it
    is left alone.

    Unlike :func:`discover` and :func:`register_client`, this does not block
    non-public hosts. The URL is the client's own metadata document, which this
    library never fetches — the authorization server resolves it — so blocking
    non-public hosts would reject a legitimate caller-hosted URL.

    Args:
        url: The HTTPS URL of the client's hosted metadata document.

    Returns:
        The validated URL, unchanged, for use as a ``client_id``.

    Raises:
        ValueError: If the URL is malformed or has an invalid port, is not
            ``https``, has no host, carries userinfo or a fragment, names no
            document path beyond a bare ``/``, or contains a ``.`` or ``..``
            path segment.
    """
    try:
        parsed = _parse_url(url)
    except ValueError as exc:
        msg = "CIMD client_id must be a valid URL"
        raise ValueError(msg) from exc
    if parsed.scheme != "https":
        msg = "CIMD client_id must be an https URL"
        raise ValueError(msg)
    if not parsed.hostname:
        msg = "CIMD client_id must be an https URL with a host"
        raise ValueError(msg)
    if parsed.username is not None or parsed.password is not None:
        msg = "CIMD client_id must not contain a username or password"
        raise ValueError(msg)
    if parsed.fragment:
        msg = "CIMD client_id must not contain a fragment"
        raise ValueError(msg)
    if not parsed.path.strip("/"):
        msg = "CIMD client_id must be an https URL with a path component"
        raise ValueError(msg)
    if any(segment in (".", "..") for segment in parsed.path.split("/")):
        msg = "CIMD client_id must not contain a . or .. path segment"
        raise ValueError(msg)
    return url


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
    client uses the first method in :data:`CONFIDENTIAL_AUTH_METHODS` the server
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
            raise McpDiscoveryError(msg, kind=FailureKind.CONFIGURATION)
        return TokenEndpointAuthMethod.NONE
    if not advertised:
        return TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
    for method in CONFIDENTIAL_AUTH_METHODS:
        if method in advertised:
            return method
    msg = "MCP server requires an unsupported client authentication method"
    raise McpDiscoveryError(msg, kind=FailureKind.CONFIGURATION)


def _honor_registered_auth_method(registered: str, secret: SecretStr | None) -> str:
    """Return the method the server registered for this client, if performable.

    The registered method (RFC 7591) is authoritative for the client, so this
    honors ``none`` for a public client and the confidential methods in
    :data:`CONFIDENTIAL_AUTH_METHODS`. It raises rather than yielding an
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
            raise McpDiscoveryError(msg, kind=FailureKind.CONFIGURATION)
        return TokenEndpointAuthMethod.NONE
    if registered in CONFIDENTIAL_AUTH_METHODS:
        if secret is None:
            msg = "MCP server registered a confidential auth method but issued no client secret"
            raise McpDiscoveryError(msg, kind=FailureKind.CONFIGURATION)
        return registered
    msg = "MCP server registered an unsupported client authentication method"
    raise McpDiscoveryError(msg, kind=FailureKind.CONFIGURATION)


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


def _parse_url(url: str) -> ParseResult:
    """Parse a URL and validate its port.

    Raises:
        ValueError: If the URL is malformed, or its port is out of range or not a number.
    """
    parsed = urlparse(url)
    # The parser validates the port only when it is read.
    _ = parsed.port
    return parsed


def _host_name(host: str) -> str:
    """Return the host without trailing dots, which name the same host."""
    return host.rstrip(".")


def _is_blocked_host(host: str) -> bool:
    """Return whether host is empty, localhost, or an IP address that is not globally reachable.

    The address registry decides what is globally reachable, so a range that is neither private
    nor reserved, such as shared address space, is still blocked.
    Reserved and multicast space stay blocked explicitly, because the registry counts parts of
    them as global, such as the NAT64 prefix that embeds any IPv4 address.
    An IPv4-mapped IPv6 address is classified as the IPv4 address it maps.
    """
    host = _host_name(host)
    if not host or _is_localhost_name(host):
        return True
    address = _parse_ip(host)
    if address is None:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return not address.is_global or address.is_reserved or address.is_multicast


def _is_localhost_name(host: str) -> bool:
    """Return whether host is ``localhost`` or a name under it."""
    return host == "localhost" or host.endswith(".localhost")


def _infer_application_type(redirect_uri: str) -> str | None:
    """Return ``native`` for a loopback redirect URI, else ``None``.

    A loopback host (``localhost`` or a loopback IP literal) is the RFC 8252
    signature of a native or CLI client. Any other redirect leaves the value
    unset so the registration request is byte-identical to one that never
    considered it.
    """
    try:
        host = _host_name(urlparse(redirect_uri).hostname or "")
    except ValueError:
        return None
    if _is_localhost_name(host):
        return ApplicationType.NATIVE
    address = _parse_ip(host)
    if address is not None and address.is_loopback:
        return ApplicationType.NATIVE
    return None


def _url_fault(caller_supplied: bool) -> tuple[type[OAuthError], FailureKind]:
    """Return the error class and kind for a URL this library will not fetch, by where the URL came from.

    A URL this library's caller passed, or one derived from it, cannot work as
    passed. A URL a fetched document named is refused.
    """
    if caller_supplied:
        return ConfigurationError, FailureKind.CONFIGURATION
    return McpDiscoveryError, FailureKind.REFUSED


def _validate_url(url: str, url_validator: UrlValidator | None, *, caller_supplied: bool) -> None:
    """Validate an MCP OAuth URL before it is requested.

    A URL is rejected when it is malformed, not HTTPS, carries userinfo, or targets
    a host that is not globally reachable. An ``OAuthError`` from ``url_validator``
    propagates unchanged, and any other validator exception is wrapped in the class
    the source decides. The validator sees only a URL that passed these checks.

    Args:
        url: The URL to check.
        url_validator: Optional policy invoked on a URL that passed the checks.
        caller_supplied: The URL is an argument of this library's caller, or derives
            from one, not a member of a fetched document.

    Raises:
        ConfigurationError: If a caller-supplied URL is rejected.
        McpDiscoveryError: If a document-supplied URL is rejected.
    """
    error_cls, kind = _url_fault(caller_supplied)
    try:
        parsed = _parse_url(url)
    except ValueError as exc:
        msg = "MCP OAuth received a malformed URL"
        raise error_cls(msg, kind=kind) from exc
    if parsed.scheme != "https":
        msg = "MCP OAuth requires HTTPS URLs"
        raise error_cls(msg, kind=kind)
    # Userinfo would be sent as credentials with the request, and could reach a log through the URL.
    if parsed.username is not None:
        msg = "MCP OAuth refused a URL that carries userinfo"
        raise error_cls(msg, kind=kind)
    if _is_blocked_host(parsed.hostname or ""):
        msg = "MCP OAuth blocked a non-public host"
        raise error_cls(msg, kind=kind)
    if url_validator is None:
        return
    try:
        url_validator(url)
    except OAuthError:
        raise
    except Exception as exc:
        # Any rejection from the caller's validator fails the operation.
        raise error_cls(str(exc), kind=kind) from exc


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
    """Return the ordered RFC 8414 metadata URLs to try, with OIDC fallback.

    A terminating slash on the identifier's path is removed before the well-known segment is inserted,
    as RFC 8414 section 3.1 requires. The identifier itself is not changed.
    """
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


async def _fetch_first_metadata(
    candidate_urls: Sequence[str],
    url_validator: UrlValidator | None,
    transport_factory: TransportFactory | None,
    what: str,
    *,
    caller_supplied: bool,
) -> dict[str, Any]:
    """Fetch and return the first candidate URL that yields a JSON object.

    Tries each URL in order through a per-URL client from ``transport_factory``,
    skipping request errors, non-200 responses, and non-object bodies. Each skip
    is logged at debug with a non-sensitive reason.

    Args:
        candidate_urls: The URLs to try, in order.
        url_validator: Optional policy invoked on each URL before it is requested.
        transport_factory: Optional factory controlling the outbound connection.
        what: The document this fetches, for the error and the debug lines.
        caller_supplied: The candidates derive from an argument of this library's
            caller, not from a fetched document.

    Returns:
        The first candidate's body that is a JSON object.

    Raises:
        ConfigurationError: If a candidate is rejected and ``caller_supplied`` says
            the candidates derive from an argument of this library's caller.
        McpDiscoveryError: If a candidate is rejected and the candidates derive from
            a fetched document, or if no candidate succeeds. The error names
            ``what``.
    """
    # A retryable failure on any candidate decides the kind, because the fallbacks answer 404 as a rule and
    # must not hide an outage on the real URL. Otherwise the last candidate's failure decides.
    kind = FailureKind.REFUSED
    retryable_kind: FailureKind | None = None
    for url in candidate_urls:
        _validate_url(url, url_validator, caller_supplied=caller_supplied)
        async with discovery_client(url, transport_factory) as client:
            try:
                response = await client.get(url)
            except httpx.InvalidURL as exc:
                # A URL the client refuses is malformed input, not a dead candidate, so it ends discovery.
                error_cls, error_kind = _url_fault(caller_supplied)
                msg = "MCP OAuth received a malformed URL"
                raise error_cls(msg, kind=error_kind) from exc
            except httpx.RequestError as exc:
                transport = http_failure(exc)
                logger.debug("MCP discovery: %s request failed (%s)", what, transport.description)
                kind = transport.kind
                retryable_kind = retryable_kind or (kind if kind.retryable else None)
                continue
            if response.status_code != 200:
                logger.debug("MCP discovery: %s returned HTTP %d", what, response.status_code)
                kind = status_failure(response.status_code).kind
                retryable_kind = retryable_kind or (kind if kind.retryable else None)
                continue
            try:
                payload = decode_json_body(response)
            except ValueError:
                logger.debug("MCP discovery: %s returned a non-JSON body", what)
                kind = FailureKind.REFUSED
                continue
            if isinstance(payload, dict):
                return payload
            logger.debug("MCP discovery: %s returned a non-object JSON body", what)
            kind = FailureKind.REFUSED
    msg = f"could not fetch {what}"
    raise McpDiscoveryError(msg, kind=retryable_kind or kind)
