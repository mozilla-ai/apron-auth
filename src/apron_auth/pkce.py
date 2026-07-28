"""PKCE (Proof Key for Code Exchange) support per RFC 7636."""

from __future__ import annotations

import base64
import hashlib
import secrets


def generate_code_verifier() -> str:
    """Generate a cryptographically random code verifier.

    Returns:
        A 43-character URL-safe string with 256 bits of entropy.
    """
    return secrets.token_urlsafe(32)


def generate_code_challenge(code_verifier: str) -> str:
    """Generate an S256 code challenge from a code verifier.

    Args:
        code_verifier: The PKCE code verifier to hash.

    Returns:
        The base64url encoding, without padding, of the verifier's
        SHA-256 digest.
    """
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
