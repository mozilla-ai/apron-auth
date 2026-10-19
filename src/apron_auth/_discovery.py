"""Shared building blocks for reading an authorization server's published metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

import httpx

from apron_auth.models import TokenEndpointAuthMethod

if TYPE_CHECKING:
    from apron_auth.protocols import TransportFactory

# Token-endpoint auth methods this library can perform for a confidential client, in preference order.
CONFIDENTIAL_AUTH_METHODS = (
    TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
)

# The time limits, in seconds, on each discovery request: 5 to connect and 10 for each other step.
DISCOVERY_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class IssuerNotDeclaredError(Exception):
    """A metadata document does not declare the issuer it was fetched for."""


def require_declared_issuer(document: Mapping[str, object], expected: str) -> None:
    """Check that a metadata document declares ``expected`` as its issuer.

    RFC 8414 section 3.3 and OpenID Connect Discovery 1.0 section 4.3 both require the declared issuer
    to be identical to the issuer identifier.
    It is compared exactly: no normalization is specified, and a trailing slash is part of the identifier.

    Args:
        document: The decoded metadata document.
        expected: The issuer identifier the document must declare.

    Raises:
        IssuerNotDeclaredError: If the document declares no issuer or a different one.
    """
    issuer = document.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        msg = "metadata declares no issuer"
        raise IssuerNotDeclaredError(msg)
    if issuer != expected:
        msg = "metadata declares a different issuer than the one it was fetched for"
        raise IssuerNotDeclaredError(msg)


def discovery_client(url: str, transport_factory: TransportFactory | None) -> httpx.AsyncClient:
    """Build the HTTP client for a metadata or registration fetch.

    The client follows no redirects, so a validated URL cannot be bounced to an unvalidated host.

    Args:
        url: The URL the client will fetch, which selects the transport.
        transport_factory: Optional factory returning the transport for ``url``.

    Returns:
        A client that routes through the factory's transport when one is given.
    """
    transport = transport_factory(url) if transport_factory is not None else None
    return httpx.AsyncClient(transport=transport, timeout=DISCOVERY_TIMEOUT, follow_redirects=False)


def str_list(value: object) -> list[str]:
    """Return the string items of ``value`` when it is a list, else an empty list."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
