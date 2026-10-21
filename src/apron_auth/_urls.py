"""Whether a URL's authority carries a credential, for every rule that refuses one."""

from __future__ import annotations

from enum import Enum, auto
from urllib.parse import urlparse


class AuthorityCredential(Enum):
    """Each member is one answer to whether a URL's authority carries a credential."""

    # The authority carries no userinfo.
    ABSENT = auto()
    # The authority cannot be read, so no answer holds for it.
    MALFORMED = auto()
    # The authority carries userinfo.
    PRESENT = auto()


def authority_credential(url: str) -> AuthorityCredential:
    """Report whether ``url`` carries a credential in its authority.

    A request derives an HTTP Basic credential from a URL's authority when its sender states none,
    so a URL that carries one decides what a client without credentials of its own presents.
    A URL that only carries the delimiter is reported as carrying a credential, because a rule
    that refuses one has no reason to admit an empty one.

    Args:
        url: The URL to read.

    Returns:
        Whether the authority carries a credential, or that the authority cannot be read.
    """
    try:
        username = urlparse(url).username
    except ValueError:
        # NOTE: Only a malformed IPv6 authority reaches this. A port that is not a number does not.
        return AuthorityCredential.MALFORMED
    if username is None:
        return AuthorityCredential.ABSENT
    return AuthorityCredential.PRESENT
