"""Fetch an OpenID provider's configuration document and check the issuer and the URLs it publishes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, assert_never
from urllib.parse import urlparse

import httpx

from apron_auth._discovery import (
    IssuerNotDeclaredError,
    IssuerRefusalReason,
    discovery_client,
    require_declared_issuer,
)
from apron_auth._http_errors import http_failure, status_failure
from apron_auth._json_body import decode_json_body
from apron_auth.errors import FailureKind, OidcDiscoveryError

if TYPE_CHECKING:
    from apron_auth.protocols import TransportFactory

# The documented logger for OpenID discovery, kept although these helpers moved out of that module.
logger = logging.getLogger("apron_auth.providers.oidc")


def require_url(
    value: Any, *, field: str, allow_insecure_http: bool, caller_supplied: bool, is_issuer: bool = False
) -> str:
    """Require ``value`` to be an absolute URL apron-auth may talk to.

    This is the one URL rule for the issuer, the document URL and every endpoint.
    The value must be a string with a scheme, a host and no fragment.
    It must use ``https`` unless ``allow_insecure_http`` is set.
    An issuer also has no query and no userinfo (OpenID Connect Discovery 1.0 section 4.1).

    Args:
        value: The raw value to check.
        field: What the value is, for the error and the warning.
        allow_insecure_http: Let an ``http`` URL through, logging a WARNING.
        is_issuer: Apply the stricter issuer rules, which forbid a query and userinfo.
        caller_supplied: The value is an argument of this library's caller, not a member of a fetched document.
            It has no default, so a call site cannot leave the source for this rule to guess.

    Returns:
        ``value``, once it passes.

    Raises:
        OidcDiscoveryError: If ``value`` is not an acceptable URL.
    """
    # The source decides the class: a caller's own URL is a configuration fault, a provider's is refused.
    kind = FailureKind.CONFIGURATION if caller_supplied else FailureKind.REFUSED
    if not isinstance(value, str) or not value:
        msg = f"OpenID {field} is not an absolute URL"
        raise OidcDiscoveryError(msg, kind=kind)
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        # The port is parsed only when read, so a port that is not a number surfaces here and not at the fetch.
        parsed.port  # noqa: B018
    except ValueError as exc:
        msg = f"OpenID {field} is malformed"
        raise OidcDiscoveryError(msg, kind=kind) from exc
    if not parsed.scheme or not hostname:
        msg = f"OpenID {field} is not an absolute URL"
        raise OidcDiscoveryError(msg, kind=kind)
    scheme = parsed.scheme.lower()
    if scheme == "http" and allow_insecure_http:
        logger.warning("OpenID %s is plain http; allowed by allow_insecure_http, use for local development only", field)
    elif scheme != "https":
        msg = f"OpenID {field} must use https (pass allow_insecure_http=True for local development)"
        raise OidcDiscoveryError(msg, kind=kind)
    if "#" in value:
        msg = f"OpenID {field} must not carry a fragment"
        raise OidcDiscoveryError(msg, kind=kind)
    if is_issuer and "?" in value:
        msg = f"OpenID {field} must not carry a query"
        raise OidcDiscoveryError(msg, kind=kind)
    if is_issuer and "@" in parsed.netloc:
        msg = f"OpenID {field} must not carry userinfo"
        raise OidcDiscoveryError(msg, kind=kind)
    return value


def require_openid_issuer(document: dict[str, Any], expected: str) -> None:
    """Require an OpenID provider's configuration document to declare ``expected`` as its issuer.

    OpenID Connect Discovery 1.0 section 4.3 requires the declared issuer to be identical to the one the document
    was fetched for, and it is compared exactly.

    Args:
        document: The decoded configuration document.
        expected: The issuer identifier the document must declare.

    Raises:
        OidcDiscoveryError: If the document declares no issuer or a different one.
    """
    try:
        require_declared_issuer(document, expected)
    except IssuerNotDeclaredError as exc:
        match exc.reason:
            case IssuerRefusalReason.ABSENT:
                msg = "OpenID provider configuration declares no issuer"
            case IssuerRefusalReason.MISMATCHED:
                msg = "OpenID provider configuration declares a different issuer than the one it was fetched for"
            case _:
                assert_never(exc.reason)
        raise OidcDiscoveryError(msg, kind=FailureKind.REFUSED) from exc


def optional_url(document: dict[str, Any], key: str, field: str, allow_insecure_http: bool) -> str | None:
    """Validate an optional endpoint when the document names one.

    Args:
        document: The configuration document.
        key: The document member to read.
        field: What the endpoint is, for errors.
        allow_insecure_http: Passed through to :func:`require_url`.

    Returns:
        The endpoint, or ``None`` when the document omits it or gives an empty string.

    Raises:
        OidcDiscoveryError: If the member is present and not empty, but not an acceptable URL.
    """
    value = document.get(key)
    if value is None or value == "":
        return None
    return require_url(value, field=field, allow_insecure_http=allow_insecure_http, caller_supplied=False)


async def fetch_document(url: str, transport_factory: TransportFactory | None) -> dict[str, Any]:
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
        # Building the client calls the caller's transport factory. Whether it refused the connection by policy or
        # failed, the fault is not the provider's and is not an outage, so it is never retried.
        msg = "could not fetch the OpenID provider configuration (outbound connection refused)"
        raise OidcDiscoveryError(msg, kind=FailureKind.UNEXPECTED) from exc
    async with client:
        try:
            response = await client.get(url)
        except httpx.RequestError as exc:
            transport = http_failure(exc)
            msg = f"could not fetch the OpenID provider configuration ({transport.description})"
            raise OidcDiscoveryError(msg, kind=transport.kind) from exc
        except httpx.InvalidURL as exc:
            msg = "could not fetch the OpenID provider configuration (invalid URL)"
            raise OidcDiscoveryError(msg, kind=FailureKind.REFUSED) from exc
        if response.status_code != 200:
            if 300 <= response.status_code < 400:
                # The target is provider-controlled text, so it is not logged.
                logger.debug("OpenID provider configuration returned HTTP %s", response.status_code)
                msg = (
                    f"OpenID provider configuration returned HTTP {response.status_code}; redirects are not "
                    "followed, so pass the canonical document URL as document_url"
                )
                raise OidcDiscoveryError(msg, kind=FailureKind.REFUSED)
            status = status_failure(response.status_code)
            msg = f"OpenID provider configuration returned {status.description}"
            raise OidcDiscoveryError(msg, kind=status.kind)
        try:
            document = decode_json_body(response)
        except ValueError as exc:
            msg = "OpenID provider configuration was not JSON"
            raise OidcDiscoveryError(msg, kind=FailureKind.REFUSED) from exc
    if not isinstance(document, dict):
        msg = "OpenID provider configuration was not a JSON object"
        raise OidcDiscoveryError(msg, kind=FailureKind.REFUSED)
    return document
