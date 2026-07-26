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
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import SecretStr

from apron_auth.errors import McpDiscoveryError
from apron_auth.models import ProviderConfig, ServerMetadata
from apron_auth.protocols import TransportFactory

UrlValidator = Callable[[str], None]

_DISCOVERY_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_WELL_KNOWN_PRM = "/.well-known/oauth-protected-resource"
_WELL_KNOWN_ASM = "/.well-known/oauth-authorization-server"
_WELL_KNOWN_OIDC = "/.well-known/openid-configuration"


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
        auth_server = next((item for item in auth_servers if isinstance(item, str)), None)
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

    return ServerMetadata(
        authorize_url=authorize_url,
        token_url=token_url,
        registration_url=registration_url,
        revocation_url=revocation_url,
        scopes_supported=_str_list(server_meta.get("scopes_supported")),
        code_challenge_methods=_str_list(server_meta.get("code_challenge_methods_supported")),
        token_endpoint_auth_methods=_str_list(server_meta.get("token_endpoint_auth_methods_supported")),
    )


def to_provider_config(
    metadata: ServerMetadata,
    *,
    client_id: str,
    client_secret: SecretStr | str | None = None,
    scopes: Sequence[str] = (),
    redirect_uri: str | None = None,
) -> ProviderConfig:
    """Fold discovered metadata and a client identity into a ProviderConfig.

    PKCE is enabled unless the server advertises code-challenge methods that
    exclude S256. A client with a secret authenticates with
    ``client_secret_post``; a secretless public client uses ``none``.

    Args:
        metadata: Metadata from :func:`discover`.
        client_id: Client identifier, pre-registered or minted via DCR.
        client_secret: Secret for a confidential client; omit for a public one.
        scopes: Scopes to request.
        redirect_uri: Redirect URI for the authorization flow.

    Returns:
        A provider configuration for :class:`~apron_auth.client.OAuthClient`.
    """
    secret = SecretStr(client_secret) if isinstance(client_secret, str) else client_secret
    methods = metadata.code_challenge_methods
    use_pkce = "S256" in methods if methods else True
    auth_method = "client_secret_post" if secret is not None else "none"
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
    )


def _str_list(value: Any) -> list[str]:
    """Return the string items of value when it is a list, else an empty list."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _is_blocked_host(host: str) -> bool:
    """Return whether host is empty, localhost, or a non-public IP literal."""
    if not host or host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _validate_url(url: str, url_validator: UrlValidator | None) -> None:
    """Validate a discovery URL before it is requested.

    Raises McpDiscoveryError when the URL is not HTTPS, targets a non-public
    host, or is rejected by ``url_validator``.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        msg = "MCP OAuth discovery requires HTTPS URLs"
        raise McpDiscoveryError(msg)
    if _is_blocked_host(parsed.hostname or ""):
        msg = "MCP OAuth discovery blocked a non-public host"
        raise McpDiscoveryError(msg)
    if url_validator is None:
        return
    try:
        url_validator(url)
    except McpDiscoveryError:
        raise
    except Exception as exc:
        # Any rejection from the caller's validator fails discovery.
        raise McpDiscoveryError(str(exc)) from exc


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


async def _fetch_first_metadata(
    candidate_urls: Sequence[str],
    url_validator: UrlValidator | None,
    transport_factory: TransportFactory | None,
    what: str,
) -> dict[str, Any]:
    """Fetch and return the first candidate URL that yields a JSON object.

    Tries each URL in order through a per-URL client from ``transport_factory``,
    skipping request errors, non-200 responses, and non-object bodies. Raises
    McpDiscoveryError describing ``what`` when no candidate succeeds.
    """
    for url in candidate_urls:
        _validate_url(url, url_validator)
        transport = transport_factory(url) if transport_factory is not None else None
        async with httpx.AsyncClient(transport=transport, timeout=_DISCOVERY_TIMEOUT, follow_redirects=False) as client:
            try:
                response = await client.get(url)
            except httpx.RequestError:
                continue
            if response.status_code != 200:
                continue
            try:
                payload = response.json()
            except ValueError:
                continue
            if isinstance(payload, dict):
                return payload
    msg = f"could not fetch {what}"
    raise McpDiscoveryError(msg)
