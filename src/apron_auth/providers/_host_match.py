"""Boundary-aware host-suffix matchers.

These helpers compare hostnames (or hostnames parsed from a
:class:`ProviderConfig` OAuth configuration) against trusted
suffixes using a label-boundary rule. They provide a shared, pure
matching implementation so provider modules can enforce consistent
host checks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig


def matches_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    """Return True if ``host`` matches any suffix on a label boundary.

    A suffix matches when ``host`` equals the suffix outright or ends
    with ``"." + suffix``. The dot anchor is the safety property: it
    rejects lookalike hosts such as ``evilexample.com`` against
    suffix ``example.com`` while still accepting legitimate
    subdomains like ``api.example.com``.
    """
    return any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)


def oauth_hosts_match(config: ProviderConfig, suffixes: tuple[str, ...]) -> bool:
    """Return True iff both OAuth URL hostnames match a provider suffix.

    Useful when a caller wants to gate behaviour on both
    ``authorize_url`` and ``token_url`` matching a provider's host
    suffix list. Requiring both — rather than either — closes a
    token-exfiltration path that otherwise applies to code paths
    deriving a userinfo URL from ``config.authorize_url``: a config
    with one provider-shaped URL and one attacker-controlled URL
    would otherwise pass an "either" check and leak the bearer token
    to the attacker host. :class:`SalesforceIdentityHandler` is the
    in-tree example of such a code path; it also re-validates the
    derived host with :func:`matches_suffix` at fetch time as defence
    in depth.
    """
    authorize_host = urlparse(config.authorize_url).hostname or ""
    token_host = urlparse(config.token_url).hostname or ""
    return matches_suffix(authorize_host, suffixes) and matches_suffix(token_host, suffixes)
