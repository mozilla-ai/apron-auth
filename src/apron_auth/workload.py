"""Verify the identity tokens a platform signs for the workloads it runs.

A workload on Google Cloud, GitHub Actions or Kubernetes can fetch a token its platform signed,
naming the workload and an audience it chose. A server that trusts the platform can accept that token
in place of a secret the workload would otherwise have to hold, as the OAuth 2.0 JWT bearer grant does (RFC 7523).

This is the server side of that exchange. No sign-in, client or nonce is involved,
so the token is checked as a JSON Web Token (RFC 7519), not as the ID token of an authorization request.
"""

from __future__ import annotations

import time
from collections.abc import Collection
from typing import TYPE_CHECKING, Any

from joserfc.errors import ExpiredTokenError, JoseError
from joserfc.jwk import RSAKey
from joserfc.jwt import ClaimsOption, JWTClaimsRegistry
from pydantic import BaseModel

from apron_auth._discovery import require_declared_issuer
from apron_auth.errors import (
    ConfigurationError,
    IdentityFetchError,
    OidcDiscoveryError,
    TokenExpiredError,
    TokenVerificationError,
)
from apron_auth.providers._jwks import IssuerSigningKeys
from apron_auth.providers.oidc import _fetch_document, _optional_url, _require_url, discovery_url

if TYPE_CHECKING:
    from collections.abc import Callable

    from apron_auth.protocols import TransportFactory

# Clock skew allowed on ``exp``, ``iat`` and ``nbf``.
_CLOCK_SKEW_SECONDS = 60
# The longest token read, in characters. A platform's token is a few kilobytes even with a certificate chain.
_MAX_TOKEN_LENGTH = 16384
# The smallest RSA key accepted, in bits (NIST SP 800-131A).
_MIN_RSA_KEY_BITS = 2048
# The shortest interval, in seconds, between discovery attempts after a failed one.
_REDISCOVER_INTERVAL_SECONDS = 60


class WorkloadIdentity(BaseModel, frozen=True):
    """What a verified workload token says about the workload that presented it.

    Attributes:
        issuer: The issuer that signed the token.
        subject: The token's ``sub``, the platform's stable identifier for the workload.
        audiences: The token's ``aud``, as a tuple even when the token names one audience.
        email: The token's ``email`` when ``email_verified`` is the boolean ``true``, otherwise ``None``.
            Google names a service account this way.
        expires_at: The token's ``exp``, in seconds since the epoch.
        claims: Every claim of the token, for a caller that matches on one this model does not lift out.
    """

    issuer: str
    subject: str
    audiences: tuple[str, ...]
    email: str | None = None
    expires_at: int
    claims: dict[str, Any]


class WorkloadTokenVerifier:
    """Verify the identity tokens one issuer signs for its workloads.

    The issuer's signing keys are found through its OpenID configuration document, unless ``jwks_url`` names them.
    Only the document's ``issuer`` and ``jwks_uri`` are read,
    so an issuer that publishes no authorization endpoint, as most workload issuers do, is discovered too.
    The keys are kept for an hour, and a token no cached key verifies refetches them early, at most once a minute.

    NOTE: Callers must not use one instance from event loops in several threads at once, because its cache is unguarded.
    """

    def __init__(
        self,
        issuer: str,
        *,
        jwks_url: str | None = None,
        transport_factory: TransportFactory | None = None,
        allow_insecure_http: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the verifier to one issuer.

        Args:
            issuer: The issuer identifier, exactly as its tokens carry it in ``iss``.
            jwks_url: The issuer's signing key set, when it is not to be discovered.
            transport_factory: Optional factory returning an httpx transport for the document and key set URLs.
                Host policy belongs here, because a check on the URL string cannot see where a hostname resolves.
            allow_insecure_http: Accept ``http`` for the issuer and the URLs it publishes, for local development only.
            clock: The monotonic clock that ages the cached keys and paces rediscovery.

        Raises:
            ConfigurationError: If ``issuer`` or ``jwks_url`` is not an acceptable URL.
        """
        try:
            self._document_url = discovery_url(issuer, allow_insecure_http=allow_insecure_http)
            if jwks_url is not None:
                _require_url(jwks_url, field="signing key set", allow_insecure_http=allow_insecure_http)
        except OidcDiscoveryError as exc:
            raise ConfigurationError(str(exc)) from exc
        self._issuer = issuer
        self._transport_factory = transport_factory
        self._allow_insecure_http = allow_insecure_http
        self._clock = clock
        self._signing_keys = (
            IssuerSigningKeys(jwks_url, transport_factory=transport_factory, clock=clock) if jwks_url else None
        )
        self._discovery_failure: str | None = None
        self._discovery_failed_at: float | None = None

    @property
    def issuer(self) -> str:
        """The issuer identifier this verifier accepts tokens from."""
        return self._issuer

    async def verify(self, token: str, *, audience: str | Collection[str] | None) -> WorkloadIdentity:
        """Return what a token says about its workload, once its signature and claims verify.

        The signature is checked against the issuer's published keys before any claim is read.
        ``iss`` must name this issuer, and ``sub``, ``aud``, ``exp`` and ``iat`` are required.
        ``nbf`` is checked when present.

        Args:
            token: A compact signed token.
            audience: The audience the token must name, or several of which it must name one.
                ``None`` checks only that it names some audience, for a caller that matches the audience itself,
                which it must then do before trusting the token.

        Returns:
            The verified identity.

        Raises:
            TokenExpiredError: If the token verifies but has expired.
            TokenVerificationError: If the token is refused for any other reason.
            IdentityFetchError: If the issuer's configuration or signing keys cannot be fetched or read,
                so no token from it can be verified now. A failed discovery is reported again for a minute.
        """
        if len(token) > _MAX_TOKEN_LENGTH:
            msg = "Workload token is longer than any issuer signs"
            raise TokenVerificationError(msg)
        signing_keys = await self._keys()
        verified = await signing_keys.verify(token)
        if isinstance(verified.key, RSAKey) and verified.key.raw_value.key_size < _MIN_RSA_KEY_BITS:
            msg = "Workload token is signed with an RSA key shorter than 2048 bits"
            raise TokenVerificationError(msg)
        claims = verified.claims
        audience_rule: ClaimsOption = {"essential": True}
        if audience is not None:
            audience_rule["values"] = [audience] if isinstance(audience, str) else list(audience)
        registry = JWTClaimsRegistry(
            leeway=_CLOCK_SKEW_SECONDS,
            iss={"essential": True, "value": self._issuer},
            sub={"essential": True},
            aud=audience_rule,
            exp={"essential": True},
            iat={"essential": True},
        )
        try:
            registry.validate(claims)
        except ExpiredTokenError as exc:
            msg = "Workload token has expired"
            raise TokenExpiredError(msg) from exc
        except (JoseError, TypeError, ValueError) as exc:
            msg = "Workload token claims did not validate"
            raise TokenVerificationError(msg) from exc
        # RFC 7519 makes ``iss`` one string, but the validator accepts a list holding it.
        if claims.get("iss") != self._issuer:
            msg = "Workload token claims did not validate"
            raise TokenVerificationError(msg)
        return _identity(self._issuer, claims)

    async def _keys(self) -> IssuerSigningKeys:
        """Return the issuer's signing keys, discovering where they are published on first use.

        Raises:
            IdentityFetchError: If discovery fails, or failed less than a minute ago.
        """
        if self._signing_keys is not None:
            return self._signing_keys
        if (
            self._discovery_failure is not None
            and self._discovery_failed_at is not None
            and self._clock() - self._discovery_failed_at < _REDISCOVER_INTERVAL_SECONDS
        ):
            raise IdentityFetchError(self._discovery_failure)
        try:
            document = await _fetch_document(self._document_url, self._transport_factory)
            require_declared_issuer(document, self._issuer, "OpenID provider configuration", OidcDiscoveryError)
            jwks_url = _optional_url(document, "jwks_uri", "signing key set", self._allow_insecure_http)
            if jwks_url is None:
                msg = "OpenID provider configuration names no signing key set"
                raise OidcDiscoveryError(msg)
        except OidcDiscoveryError as exc:
            self._discovery_failure = f"Failed to discover the issuer's signing keys: {exc}"
            self._discovery_failed_at = self._clock()
            raise IdentityFetchError(self._discovery_failure) from exc
        self._discovery_failure = None
        # Concurrent first calls may each discover, and the last to finish keeps its key set, which is equivalent.
        self._signing_keys = IssuerSigningKeys(jwks_url, transport_factory=self._transport_factory, clock=self._clock)
        return self._signing_keys


def _identity(issuer: str, claims: dict[str, Any]) -> WorkloadIdentity:
    """Lift the identity out of validated claims.

    Raises:
        TokenVerificationError: If ``sub``, ``aud`` or ``exp`` does not have the type RFC 7519 gives it.
    """
    subject = claims["sub"]
    audience = claims["aud"]
    audiences = (audience,) if isinstance(audience, str) else audience
    expires_at = claims["exp"]
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(audiences, list | tuple)
        or not audiences
        or not all(isinstance(value, str) for value in audiences)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int | float)
    ):
        msg = "Workload token claims did not validate"
        raise TokenVerificationError(msg)
    email = claims.get("email")
    # Only the boolean ``true`` counts, so a string ``"true"`` does not verify an address.
    verified_email = email if claims.get("email_verified") is True and isinstance(email, str) and email else None
    return WorkloadIdentity(
        issuer=issuer,
        subject=subject,
        audiences=tuple(audiences),
        email=verified_email,
        expires_at=int(expires_at),
        claims=claims,
    )
