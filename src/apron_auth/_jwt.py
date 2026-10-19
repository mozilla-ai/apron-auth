"""Parse compact JSON Web Signature (JWS) tokens, such as ID tokens, with size limits that real issuers need."""

from __future__ import annotations

import json
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jws import CompactSignature, JWSRegistry

from apron_auth.errors import TokenValidationReason

# The clock difference, in seconds, allowed between this client and another host wherever a time is checked.
CLOCK_SKEW_SECONDS = 60

# A certificate chain (``x5c``) in the header and an 8192-bit RSA signature both exceed the library's default limits.
_MAX_HEADER_LENGTH = 16384
_MAX_SIGNATURE_LENGTH = 2048


def compact_claims(compact: CompactSignature) -> dict[str, Any] | None:
    """Return the claims of a parsed compact token.

    Args:
        compact: The parsed compact token.

    Returns:
        The token's claims, or ``None`` when they are not a JSON object.
    """
    try:
        claims = json.loads(compact.payload)
    except (RecursionError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


def jws_registry(algorithms: list[str] | None = None) -> JWSRegistry:
    """Return a JSON Web Signature (JWS) registry that ignores non-critical header parameters it does not know.

    RFC 7515 allows a reader to ignore them.

    Args:
        algorithms: The algorithms the registry accepts, or ``None`` for one that only parses.

    Returns:
        The registry, with size limits large enough for a certificate chain in the header.
    """
    registry = JWSRegistry(algorithms=algorithms, strict_check_header=False)
    registry.max_header_length = _MAX_HEADER_LENGTH
    registry.max_signature_length = _MAX_SIGNATURE_LENGTH
    return registry


def parse_compact(token: str) -> CompactSignature:
    """Return the parsed form of a compact signed token, without checking its signature.

    Args:
        token: A compact signed token.

    Returns:
        The parsed token.

    Raises:
        ValueError: If the token is not a compact signed token with a JSON object header and an encoded payload.
    """
    msg = "The token is not a compact signed token"
    try:
        compact = jws.extract_compact(token.encode(), registry=jws_registry())
    except (JoseError, RecursionError, TypeError, ValueError) as exc:
        raise ValueError(msg) from exc
    header = compact.headers()
    # RFC 7797 ``b64: false`` sends the payload unencoded, and an ID token never uses that form.
    if not isinstance(header, dict) or header.get("b64", True) is not True:
        raise ValueError(msg)
    return compact


def unverified_claims(token: str) -> dict[str, Any]:
    """Return the claims of a compact signed token without checking its signature.

    NOTE: Callers must trust the channel the token came from, because nothing here proves who signed it.

    Args:
        token: A compact signed token.

    Returns:
        The token's claims.

    Raises:
        ValueError: If the token is not a compact signed token, or its claims are not a JSON object.
    """
    claims = compact_claims(parse_compact(token))
    if claims is None:
        msg = "The token's claims are not a JSON object"
        raise ValueError(msg)
    return claims


def claim_refusal_reason(claim: object) -> TokenValidationReason:
    """Return the reason a token is refused when the named claim does not validate.

    Args:
        claim: The claim name the validator reported, or ``None`` when it reported none.

    Returns:
        ``AUDIENCE`` for ``aud``, ``UNKNOWN_ISSUER`` for ``iss``, else ``CLAIMS``.
    """
    if claim == "aud":
        return TokenValidationReason.AUDIENCE
    if claim == "iss":
        return TokenValidationReason.UNKNOWN_ISSUER
    return TokenValidationReason.CLAIMS
