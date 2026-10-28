"""What a URL states: its authority, its host and its scheme."""

from __future__ import annotations

import ipaddress
import socket
from enum import Enum, auto
from urllib.parse import parse_qs, urlparse

import httpx


class AuthorityCredential(Enum):
    """Each member is one answer to whether a URL's authority carries a credential."""

    # The authority carries no userinfo.
    ABSENT = auto()
    # The authority cannot be read, so no answer holds for it.
    MALFORMED = auto()
    # The authority carries userinfo.
    PRESENT = auto()


def _scheme_and_host(url: str) -> tuple[str, str] | None:
    """Return the scheme and host of ``url``, or None when a request cannot be sent to it as written.

    Args:
        url: The URL to read.

    Returns:
        The scheme and the host, or ``None`` when the URL cannot be read.
    """
    try:
        parsed = urlparse(url)
        # The port is parsed only when read, so one that is not a number surfaces here.
        _ = parsed.port
        # The HTTP client's parser is stricter than urlparse, so a URL it cannot request is no URL here.
        httpx.URL(url)
    except (ValueError, httpx.InvalidURL):
        return None
    return parsed.scheme, parsed.hostname or ""


def authority_credential(url: str) -> AuthorityCredential:
    """Report whether ``url`` carries a credential in its authority.

    A request derives an HTTP Basic credential from a URL's authority when its sender states none,
    so a URL that carries one decides what a client without credentials of its own presents.
    A URL that only carries the delimiter is reported as carrying a credential, because a rule
    that refuses one has no reason to admit an empty one.
    An authority an HTTP client cannot read, by its host or by its port, is reported as unreadable.

    Args:
        url: The URL to read.

    Returns:
        Whether the authority carries a credential, or that the authority cannot be read.
    """
    if _scheme_and_host(url) is None:
        return AuthorityCredential.MALFORMED
    try:
        username = urlparse(url).username
    except ValueError:
        return AuthorityCredential.MALFORMED
    if username is None:
        return AuthorityCredential.ABSENT
    return AuthorityCredential.PRESENT


def host_name(host: str) -> str:
    """Return the host without trailing dots, which name the same host.

    Args:
        host: The host to read.

    Returns:
        The host, without a trailing dot.
    """
    return host.rstrip(".")


def is_localhost_name(host: str) -> bool:
    """Return whether host is ``localhost`` or a name under it.

    Args:
        host: The host to read.

    Returns:
        Whether the host names the local machine by name.
    """
    return host == "localhost" or host.endswith(".localhost")


def is_loopback_host(host: str) -> bool:
    """Return whether host names the loopback interface, by name or by a canonical address.

    NOTE: Only the name ``localhost`` and a canonical loopback address count.
    A name under ``localhost`` and a legacy numeric form do not, because resolvers differ over both.

    Args:
        host: The host to read.

    Returns:
        Whether a request to the host stays on the machine that sent it.
    """
    host = host_name(host)
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # NOTE: An IPv4-mapped IPv6 address is read as the address it maps. Not every interpreter
    # reports the mapping itself as loopback, and this rule cannot answer by interpreter.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def is_plain_http(url: str) -> bool:
    """Return whether ``url`` states ``http`` and names a host.

    Args:
        url: The URL to read.

    Returns:
        Whether the URL states ``http`` and names a host.
    """
    readable = _scheme_and_host(url)
    if readable is None:
        return False
    scheme, host = readable
    return scheme == "http" and bool(host)


def matches_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    """Return whether ``host`` matches any of ``suffixes`` on a label boundary.

    A suffix matches when ``host`` equals it or ends with a dot and it, ignoring case.
    The dot is the safety property: it refuses a lookalike such as ``evilexample.com`` against the
    suffix ``example.com``, while still accepting a subdomain such as ``api.example.com``.

    Args:
        host: The hostname to read.
        suffixes: The trusted suffixes to match it against.

    Returns:
        Whether the host matches any suffix on a label boundary.
    """
    # A DNS name is case-insensitive, and this answer decides where a credential may be sent.
    name = host.lower()
    return any(name == suffix.lower() or name.endswith("." + suffix.lower()) for suffix in suffixes)


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the address ``host`` names, or None when it names no address.

    A legacy numeric form such as ``2130706433``, ``0x7f000001`` or ``127.1`` names an address,
    because a resolver dials it as one although the standard library reads only canonical text.

    Args:
        host: The host to read.

    Returns:
        The address the host names, or ``None`` when it names no address.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(host)
    except (OSError, ValueError):
        return None
    return ipaddress.ip_address(packed)


def query_parameters(url: str) -> dict[str, str | list[str]]:
    """Return the parameters ``url`` states in its query.

    A parameter written with no value states that parameter with an empty value, because a rule
    that reads the query decides on the names it holds rather than on what they are set to.
    A URL with no query, and one that cannot be read at all, both state no parameters.

    Args:
        url: The URL to read.

    Returns:
        The parameters, each with its value, or with its values where the query repeats the name.
    """
    try:
        query = urlparse(url).query
    except ValueError:
        return {}
    return {
        name: values[0] if len(values) == 1 else values
        for name, values in parse_qs(query, keep_blank_values=True).items()
    }


def url_host(url: str) -> str:
    """Return the host ``url`` names, or an empty string when it names none.

    A URL a request cannot be sent to as written names no host, so a rule that decides where a
    credential may be sent reads no host from it rather than part of one.

    Args:
        url: The URL to read.

    Returns:
        The host, lowercased as a DNS name is, or an empty string.
    """
    readable = _scheme_and_host(url)
    return "" if readable is None else readable[1]


def uses_allowed_transport(url: str, *, plain_http_allowed: bool) -> bool:
    """Return whether what a request sends to ``url`` may cross the network the URL states.

    ``https`` always may, and so does plain ``http`` to a loopback host, because that request
    reaches no network.
    Plain ``http`` to any other host may only when ``plain_http_allowed``.
    No other scheme may, and neither may a URL that cannot be read or names no host.

    Args:
        url: The URL to read.
        plain_http_allowed: Plain ``http`` to a host on the network is accepted.

    Returns:
        Whether a request may be sent to the URL as it is written.
    """
    return uses_secure_transport(url) or (plain_http_allowed and is_plain_http(url))


def uses_secure_transport(url: str) -> bool:
    """Return whether what a request sends to ``url`` is protected from the network it crosses.

    Only ``https`` protects it.
    Plain ``http`` to a loopback host counts, because the request reaches no network.
    Every other scheme states no protection, as does a URL that cannot be read or names no host.

    Args:
        url: The URL to read.

    Returns:
        Whether what is sent to the URL is protected in transit.
    """
    readable = _scheme_and_host(url)
    if readable is None:
        return False
    scheme, host = readable
    if scheme == "https":
        return bool(host)
    return scheme == "http" and is_loopback_host(host)
