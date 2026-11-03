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
from joserfc.jwt import ClaimsOption, JWTClaimsRegistry
from pydantic import BaseModel

from apron_auth._clock import CLOCK_SKEW_SECONDS
from apron_auth._jwt import claim_refusal_reason, compact_claims, parse_compact
from apron_auth._loop_lock import LoopLock
from apron_auth._numbers import finite_number
from apron_auth._urls import is_plain_http
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    OidcDiscoveryError,
    TokenExpiredError,
    TokenValidationError,
    TokenValidationReason,
)
from apron_auth.models import TimeoutPolicy, UrlField, WorkloadIssuer
from apron_auth.providers._jwks import IssuerSigningKeys
from apron_auth.providers._openid_documents import fetch_document, optional_url, require_openid_issuer, require_url
from apron_auth.providers.oidc import discovery_url

if TYPE_CHECKING:
    from collections.abc import Callable

    from apron_auth.protocols import TransportFactory

# The longest token read, in characters. A platform's token is a few kilobytes even with a certificate chain.
_MAX_TOKEN_LENGTH = 16384
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


class _TrustedIssuer:
    """One accepted issuer, and the signing keys its tokens are checked against.

    The keys are found through the issuer's OpenID configuration document, unless the issuer names them.
    Only the document's ``issuer`` and ``jwks_uri`` are read, so an issuer that publishes no authorization
    endpoint, as most workload issuers do, is discovered too.
    The document is read once, and a failed read is reported again for a minute before another is attempted.
    """

    def __init__(
        self,
        issuer: WorkloadIssuer,
        *,
        transport_factory: TransportFactory | None,
        timeouts: TimeoutPolicy,
        clock: Callable[[], float],
    ) -> None:
        """Bind to one issuer, refusing a URL this library could not fetch from.

        Args:
            issuer: The issuer to accept tokens from.
            transport_factory: Optional factory returning an httpx transport for the document and key set URLs.
            timeouts: The limits on the document and key set fetches.
            clock: The monotonic clock that paces rediscovery.

        Raises:
            ConfigurationError: If the issuer identifier or the key set URL is not one a request can be sent to.
        """
        # The issuer model has settled what transport its URLs may state, so the URL rule is asked only for
        # what it adds: an issuer identifier carries no query, and either URL has to be requestable as written.
        try:
            self._document_url = discovery_url(issuer.issuer, allow_insecure_http=is_plain_http(issuer.issuer))
            if issuer.jwks_url is not None:
                require_url(
                    issuer.jwks_url,
                    field="signing key set",
                    allow_insecure_http=is_plain_http(issuer.jwks_url),
                    caller_supplied=True,
                )
        except OidcDiscoveryError as exc:
            raise ConfigurationError(str(exc)) from exc
        self._issuer = issuer.issuer
        self._plain_http_key_set = UrlField.JWKS_URL in issuer.allow_insecure_http_for
        self._transport_factory = transport_factory
        self._timeouts = timeouts
        self._clock = clock
        self._signing_keys = self._key_set(issuer.jwks_url) if issuer.jwks_url else None
        self._discovery_failure: tuple[str, FailureKind] | None = None
        self._discovery_failed_at: float | None = None
        self._discovery_lock = LoopLock()

    @property
    def issuer(self) -> str:
        """The issuer identifier, exactly as this issuer's tokens carry it in ``iss``."""
        return self._issuer

    async def keys(self) -> IssuerSigningKeys:
        """Return the issuer's signing keys, discovering where they are published on first use.

        Raises:
            IdentityFetchError: If discovery fails, or failed less than a minute ago.
        """
        if self._signing_keys is not None:
            return self._signing_keys
        # Concurrent first calls wait for one discovery, so a burst at startup fetches the document once.
        async with self._discovery_lock():
            if self._signing_keys is not None:
                return self._signing_keys
            if (
                self._discovery_failure is not None
                and self._discovery_failed_at is not None
                and self._clock() - self._discovery_failed_at < _REDISCOVER_INTERVAL_SECONDS
            ):
                message, kind = self._discovery_failure
                raise IdentityFetchError(message, kind=kind)
            try:
                document = await fetch_document(self._document_url, self._transport_factory, self._timeouts)
                require_openid_issuer(document, self._issuer)
                jwks_url = optional_url(
                    document, key="jwks_uri", field="signing key set", allow_insecure_http=self._plain_http_key_set
                )
                if jwks_url is None:
                    msg = "OpenID provider configuration names no signing key set"
                    raise OidcDiscoveryError(msg, kind=FailureKind.REFUSED)
            except OidcDiscoveryError as exc:
                msg = f"Failed to discover the issuer's signing keys: {exc}"
                # Only the message and the kind are kept, so the failed request's objects are not held for a minute.
                self._discovery_failure = (msg, exc.kind)
                self._discovery_failed_at = self._clock()
                raise IdentityFetchError(msg, kind=exc.kind) from exc
            self._discovery_failure = None
            self._signing_keys = self._key_set(jwks_url)
            return self._signing_keys

    def _key_set(self, jwks_url: str) -> IssuerSigningKeys:
        """Return the signing keys published at ``jwks_url``."""
        return IssuerSigningKeys(jwks_url, transport_factory=self._transport_factory, clock=self._clock)


class WorkloadTokenVerifier:
    """Verify the identity tokens one or more issuers sign for their workloads.

    A token is checked against the published keys of the issuer its ``iss`` names, and against no other
    accepted issuer's, so accepting several issuers never lets one of them sign for another.
    An RSA key shorter than 2048 bits is never used.

    NOTE: Callers must not use one instance from event loops in several threads at once, because its caches
    are unguarded.
    """

    def __init__(
        self,
        issuers: Collection[WorkloadIssuer],
        *,
        transport_factory: TransportFactory | None = None,
        timeouts: TimeoutPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the verifier to the issuers whose tokens it accepts.

        Args:
            issuers: The issuers to accept tokens from, each named once.
            transport_factory: Optional factory returning an httpx transport for the document and key set URLs.
                Host policy belongs here, because a check on the URL string cannot see where a hostname resolves.
            timeouts: The limits on the document and key set fetches.
                Defaults to :class:`~apron_auth.models.TimeoutPolicy`'s own.
            clock: The monotonic clock that ages the cached keys and paces rediscovery.

        Raises:
            ConfigurationError: If ``issuers`` states no issuer or anything but an issuer, names one issuer
                more than once, or names one whose URLs a request could not be sent to.
        """
        stated = list(issuers) if isinstance(issuers, Collection) and not isinstance(issuers, str) else []
        if not stated or not all(isinstance(entry, WorkloadIssuer) for entry in stated):
            msg = "A verifier accepts one or more issuers, each stated as a WorkloadIssuer"
            raise ConfigurationError(msg)
        self._timeouts = timeouts or TimeoutPolicy()
        self._issuers: dict[str, _TrustedIssuer] = {}
        for entry in stated:
            if entry.issuer in self._issuers:
                msg = "A verifier accepts each issuer once, and one of them is named more than once"
                raise ConfigurationError(msg)
            self._issuers[entry.issuer] = _TrustedIssuer(
                entry, transport_factory=transport_factory, timeouts=self._timeouts, clock=clock
            )

    @property
    def issuers(self) -> tuple[str, ...]:
        """The issuer identifiers this verifier accepts tokens from, in the order they were stated."""
        return tuple(self._issuers)

    async def verify(self, token: str, *, audience: str | Collection[str] | None) -> WorkloadIdentity:
        """Return what a token says about its workload, once its signature and claims verify.

        The token's ``iss`` selects the issuer, and the signature is checked against that issuer's published
        keys before any claim is read. ``iss`` must name the selected issuer, and ``sub``, ``aud``, ``exp``
        and ``iat`` are required. ``nbf`` is checked when present.

        Args:
            token: A compact signed token.
            audience: The audience the token must name, or a non-empty collection of which it must name one.
                ``None`` checks only that it names some audience, for a caller that matches the audience itself,
                which it must then do before trusting the token.

        Returns:
            The verified identity.

        Raises:
            ConfigurationError: If ``audience`` is an empty collection or holds anything but non-empty strings.
                An empty one would accept every audience, so ``None`` must say that instead.
            TokenExpiredError: If the token verifies but has expired.
            TokenValidationError: If the token is refused for any other reason.
            IdentityFetchError: If the issuer's configuration or signing keys cannot be fetched or read,
                so no token from it can be verified now. A failed discovery is reported again for a minute.
        """
        audience_rule: ClaimsOption = {"essential": True}
        if audience is not None:
            values = [audience] if isinstance(audience, str) else list(audience)
            if not values or not all(isinstance(value, str) and value for value in values):
                msg = "audience must name one or more audiences, or be None to leave the match to the caller"
                raise ConfigurationError(msg)
            audience_rule["values"] = values
        if len(token) > _MAX_TOKEN_LENGTH:
            msg = "Workload token is longer than any issuer signs"
            raise TokenValidationError(msg, reason=TokenValidationReason.MALFORMED)
        # A token that is not one is refused before discovery, so it is never reported as an outage.
        try:
            compact = parse_compact(token)
        except ValueError as exc:
            msg = "Workload token is not a compact signed token"
            raise TokenValidationError(msg, reason=TokenValidationReason.MALFORMED) from exc
        unverified = compact_claims(compact)
        if unverified is None:
            msg = "Workload token claims are not a JSON object"
            raise TokenValidationError(msg, reason=TokenValidationReason.MALFORMED)
        trusted = self._trusted_issuer(unverified.get("iss"))
        signing_keys = await trusted.keys()
        claims = (await signing_keys.verify(token, self._timeouts)).claims
        registry = JWTClaimsRegistry(
            leeway=CLOCK_SKEW_SECONDS,
            iss={"essential": True, "value": trusted.issuer},
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
            raise TokenValidationError(msg, reason=claim_refusal_reason(getattr(exc, "claim", None))) from exc
        # RFC 7519 makes ``iss`` one string, but the validator accepts a list holding it.
        if claims.get("iss") != trusted.issuer:
            msg = "Workload token claims did not validate"
            raise TokenValidationError(msg, reason=TokenValidationReason.UNKNOWN_ISSUER)
        return _identity(trusted.issuer, claims)

    def _trusted_issuer(self, issuer_claim: object) -> _TrustedIssuer:
        """Return the accepted issuer that a token's ``iss`` names.

        NOTE: The claim is read before any signature is checked, so it only selects which published keys the
        token is then checked against. It grants nothing: the signature check and the claim validation that
        follow both hold the token to the issuer selected here.

        Args:
            issuer_claim: The token's ``iss``, as it arrived.

        Returns:
            The accepted issuer the claim names.

        Raises:
            TokenValidationError: If the claim is not the identifier of an accepted issuer.
        """
        trusted = self._issuers.get(issuer_claim) if isinstance(issuer_claim, str) else None
        if trusted is None:
            msg = "Workload token names an issuer this verifier does not accept"
            raise TokenValidationError(msg, reason=TokenValidationReason.UNKNOWN_ISSUER)
        return trusted


def _identity(issuer: str, claims: dict[str, Any]) -> WorkloadIdentity:
    """Lift the identity out of validated claims.

    Raises:
        TokenValidationError: If ``sub``, ``aud`` or ``exp`` does not have the type RFC 7519 gives it,
            or ``exp`` is not a finite number.
    """
    subject = claims["sub"]
    audience = claims["aud"]
    audiences = (audience,) if isinstance(audience, str) else audience
    # A non-finite expiry compares false against every time, so the claim validator does not refuse it.
    expires_at = finite_number(claims["exp"])
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(audiences, list | tuple)
        or not audiences
        or not all(isinstance(value, str) for value in audiences)
        or expires_at is None
    ):
        msg = "Workload token claims did not validate"
        raise TokenValidationError(msg, reason=TokenValidationReason.CLAIMS)
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
