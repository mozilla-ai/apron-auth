"""Shared building blocks for reading an authorization server's published metadata."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum, auto
from typing import TYPE_CHECKING

import httpx

from apron_auth._timeouts import httpx_timeout
from apron_auth.models import TokenEndpointAuthMethod

if TYPE_CHECKING:
    from apron_auth.models import TimeoutPolicy
    from apron_auth.protocols import TransportFactory

# Token-endpoint auth methods this library can perform for a confidential client, in preference order.
CONFIDENTIAL_AUTH_METHODS = (
    TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
)


class IssuerRefusalReason(Enum):
    """Each member is one issuer condition a metadata document can fail."""

    # The document names no issuer, or names one that is not a non-empty string.
    ABSENT = auto()
    # The document names an issuer other than the one it was fetched for.
    MISMATCHED = auto()


class IssuerNotDeclaredError(Exception):
    """Internal refusal of a metadata document that does not declare the issuer it was fetched for.

    NOTE: This is not one of the library's errors, so each caller must wrap it in the error for its own phase.
    """

    def __init__(self, reason: IssuerRefusalReason) -> None:
        """Create the refusal.

        Args:
            reason: Which issuer condition the document failed.
        """
        super().__init__(reason.name)
        self.reason = reason


class MetadataListNotStringsError(Exception):
    """Internal refusal of a metadata list member that gates a decision and is not a list of strings.

    NOTE: This is not one of the library's errors, so each caller must wrap it in the error for its own phase.

    Attributes:
        key: The member that was refused.
    """

    def __init__(self, key: str) -> None:
        """Create the refusal.

        Args:
            key: The member that is not a list of strings.
        """
        super().__init__(key)
        self.key = key


def require_declared_issuer(document: Mapping[str, object], expected: str) -> None:
    """Check that a metadata document declares ``expected`` as its issuer.

    RFC 8414 section 3.3 and OpenID Connect Discovery 1.0 section 4.3 both require the declared issuer
    to be identical to the issuer identifier.
    It is compared exactly: no normalization is specified, and a trailing slash is part of the identifier.

    Args:
        document: The decoded metadata document.
        expected: The issuer identifier the document must declare.

    Raises:
        IssuerNotDeclaredError: If the document declares no issuer or a different one, naming which in ``reason``.
    """
    issuer = document.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        raise IssuerNotDeclaredError(IssuerRefusalReason.ABSENT)
    if issuer != expected:
        raise IssuerNotDeclaredError(IssuerRefusalReason.MISMATCHED)


def discovery_client(
    url: str, transport_factory: TransportFactory | None, timeouts: TimeoutPolicy
) -> httpx.AsyncClient:
    """Build the HTTP client for a metadata or registration fetch.

    The client follows no redirects, so a validated URL cannot be bounced to an unvalidated host.

    NOTE: The limits this applies bound each step of a request. A caller must also bound the request
    itself with ``within_request_limit``, because a document arriving slowly outlives every step limit.

    Args:
        url: The URL the client will fetch, which selects the transport.
        transport_factory: Optional factory returning the transport for ``url``.
        timeouts: The limits in force for the fetch.

    Returns:
        A client that routes through the factory's transport when one is given.
    """
    transport = transport_factory(url) if transport_factory is not None else None
    return httpx.AsyncClient(transport=transport, timeout=httpx_timeout(timeouts), follow_redirects=False)


def str_list(value: object) -> list[str]:
    """Return the string items of ``value`` when it is a list, else an empty list."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def strict_str_list(document: Mapping[str, object], key: str) -> list[str]:
    """Return a metadata list member that gates a decision, refusing a malformed one.

    A present but malformed value is an error rather than an absence. Read leniently it becomes an empty
    list, which is what an unadvertised member looks like, so a reader cannot tell a server that advertised
    nothing from one whose value it could not read, and the default for the first is applied to the second.

    Args:
        document: The metadata document.
        key: The member to read.

    Returns:
        The strings the member states, or ``[]`` when it is absent.

    Raises:
        MetadataListNotStringsError: If the member is present and is not a list of strings.
    """
    value = document.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise MetadataListNotStringsError(key)
    return value
