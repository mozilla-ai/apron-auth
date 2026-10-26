"""Whether the OAuth endpoints a configuration names are a provider's own hosts."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from apron_auth._urls import matches_suffix

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig


def oauth_hosts_match(config: ProviderConfig, suffixes: tuple[str, ...]) -> bool:
    """Report whether both OAuth URL hostnames match a provider suffix.

    Useful when a caller wants to gate behavior on both
    ``authorize_url`` and ``token_url`` matching a provider's host
    suffix list. Requiring both — rather than either — closes a
    token-exfiltration path that otherwise applies to code paths
    deriving a userinfo URL from ``config.authorize_url``: a config
    with one provider-shaped URL and one attacker-controlled URL
    would otherwise pass an "either" check and leak the bearer token
    to the attacker host. :class:`SalesforceIdentityHandler` is the
    in-tree example of such a code path; it also re-validates the
    derived host with :func:`matches_suffix` at fetch time as defense
    in depth.

    Args:
        config: The provider configuration whose ``authorize_url`` and
            ``token_url`` hosts are checked.
        suffixes: The trusted provider host suffixes.

    Returns:
        ``True`` only when both the authorize and token URL hosts match a
        suffix.
    """
    authorize_host = urlparse(config.authorize_url).hostname or ""
    token_host = urlparse(config.token_url).hostname or ""
    return matches_suffix(authorize_host, suffixes) and matches_suffix(token_host, suffixes)
