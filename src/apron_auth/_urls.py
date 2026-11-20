"""What a URI states: its authority, its host, its scheme, and whether it can name a resource.

Most rules here read a URL's authority, so they answer nothing for a URI that names none.
A resource indicator is the exception, because RFC 8707 accepts any absolute URI, a URN among them.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from enum import Enum, auto
from urllib.parse import parse_qs, urlparse, urlsplit

import httpx

# RFC 3986 section 3.2: an authority is an optional userinfo, a host and an optional port. A bracket is
# written only around an address literal, which is the one place section 3 puts one. A literal carries
# percent escapes too, because RFC 6874 writes a zone identifier after an escaped delimiter.
_URI_AUTHORITY = re.compile(
    r"\A(?:(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})*@)?"
    r"(?:\[(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})+\]"
    r"|(?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*)"
    r"(?::[0-9]*)?\Z"
)
# RFC 3986 sections 3.3 and 3.4: the characters a path or a query carries, a percent escape written whole.
# A bracket is no part of either, so one outside an authority is not a URI however the parser reads it.
_URI_PATH_OR_QUERY = re.compile(r"\A(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*\Z")
# RFC 3986 section 3.1: a scheme opens with a letter and carries letters, digits and three marks.
_URI_SCHEME = re.compile(r"\A[A-Za-z][A-Za-z0-9+\-.]*\Z")
# Every character RFC 3986 puts anywhere in a URI, read against the value as it arrived. The standard
# parser deletes some characters and strips others off both ends before it reports a component, so a rule
# reading components alone cannot see them, whichever set that parser decides to normalize.
_URI_REPERTOIRE = re.compile(r"\A[A-Za-z0-9\-._~!$&'()*+,;=:/?#\[\]@%]*\Z")


class AuthorityCredential(Enum):
    """Each member is one answer to whether a URL's authority carries a credential."""

    # The authority carries no userinfo.
    ABSENT = auto()
    # The authority cannot be read, so no answer holds for it.
    MALFORMED = auto()
    # The authority carries userinfo.
    PRESENT = auto()


class ResourceIndicatorFault(Enum):
    """Each member is one reason a value cannot serve as an RFC 8707 resource indicator."""

    # The value carries a fragment.
    FRAGMENT = auto()
    # The value cannot be read as a URI at all.
    MALFORMED = auto()
    # The value states no scheme, so it is relative rather than absolute.
    RELATIVE = auto()


def _scheme_and_host(url: str) -> tuple[str, str] | None:
    """Return the scheme and host of ``url``, or None when a request cannot be sent to it as written.

    The scheme and host are the HTTP client's own, the parser that resolves and dials them, so a rule
    built on them answers for the request that is sent rather than for a second reading of the URL.
    The standard library's parser still has to read the port, which it refuses in forms the client
    accepts and then drops, so a URL stating a port it never sends is no URL here. That parser can
    only narrow what this accepts, never widen it.

    Args:
        url: The URL to read.

    Returns:
        The scheme and the host, or ``None`` when the URL cannot be read.
    """
    try:
        # The port is parsed only when read, so one that is not a number surfaces here.
        _ = urlparse(url).port
        parsed = httpx.URL(url)
        host = parsed.raw_host.decode("ascii")
    except (UnicodeDecodeError, ValueError, httpx.InvalidURL):
        return None
    return parsed.scheme, host


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

    A trailing root dot names the same host, so ``localhost.`` and ``127.0.0.1.`` both name it.

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


def resource_indicator_fault(resource: str) -> ResourceIndicatorFault | None:
    """Report why a value cannot serve as an RFC 8707 resource indicator, if it cannot.

    RFC 8707 section 2 requires an absolute URI (RFC 3986 section 4.3): it states a scheme, it carries no
    fragment, and its authority, path and query are each written in the characters RFC 3986 allows them.
    A value carrying no fault binds a token's audience to the service it names.

    NOTE: The standard parser reads a scheme off a string it never checked for URI syntax, so each
    component is read here rather than left to it. The components are checked separately because a
    bracket is a URI character in an authority and no part of a path or a query. The value's own
    characters are read before it is parsed at all, because that parser deletes some and strips others
    off both ends, and a component it reports no longer carries what it removed.

    Args:
        resource: The value to read.

    Returns:
        The fault that disqualifies the value, or None when it qualifies.
    """
    if "#" in resource:
        return ResourceIndicatorFault.FRAGMENT
    if not _URI_REPERTOIRE.match(resource):
        return ResourceIndicatorFault.MALFORMED
    try:
        parts = urlsplit(resource)
    except ValueError:
        return ResourceIndicatorFault.MALFORMED
    if not parts.scheme:
        return ResourceIndicatorFault.RELATIVE
    if not _URI_SCHEME.match(parts.scheme) or not _URI_AUTHORITY.match(parts.netloc):
        return ResourceIndicatorFault.MALFORMED
    if not _URI_PATH_OR_QUERY.match(parts.path) or not _URI_PATH_OR_QUERY.match(parts.query):
        return ResourceIndicatorFault.MALFORMED
    return None


def url_host(url: str) -> str:
    """Return the host a request to ``url`` would reach, or an empty string when it would reach none.

    The host is read with the HTTP client's own parser, the one that resolves and dials it, so a rule
    deciding where a credential may be sent reads the host the request reaches rather than a second
    parser's answer about it. Two parsers disagreeing over an authority would otherwise let a rule
    accept one host while the request reached another.
    The name is the form the client dials, so an internationalized host reads as its ASCII form.
    NOTE: A URL the client refuses outright reads as no host rather than raising.

    Args:
        url: The URL to read.

    Returns:
        The host, as the client would dial it, or an empty string.
    """
    try:
        return httpx.URL(url).raw_host.decode("ascii")
    except (UnicodeDecodeError, ValueError, httpx.InvalidURL):
        return ""


def uses_allowed_transport(url: str, *, plain_http_allowed: bool) -> bool:
    """Return whether what a request sends to ``url`` may cross the network the URL states.

    ``https`` always may, and so does plain ``http`` to a loopback host, because that request
    reaches no network.
    Plain ``http`` to any other host may only when ``plain_http_allowed``.
    No other scheme may, and neither may a URL that cannot be read or names no host.
    The host is the one the HTTP client dials, so a host this accepts is the host the request reaches.

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
