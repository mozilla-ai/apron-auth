"""Verify ID tokens against an issuer's published JSON Web Key Set (JWKS)."""

from __future__ import annotations

import logging
import time
from enum import Enum, StrEnum, auto
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx
from joserfc import jwk, jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey, OKPKey, RSAKey
from joserfc.jws import CompactSignature, JWSRegistry

from apron_auth._discovery import discovery_client
from apron_auth._http_errors import http_failure
from apron_auth._json_body import decode_json_body
from apron_auth._jwt import compact_claims, jws_registry, parse_compact
from apron_auth._loop_lock import LoopLock
from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    TokenValidationError,
    TokenValidationReason,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from apron_auth.protocols import TransportFactory

logger = logging.getLogger(__name__)

# The age, in seconds, after which the cached key set is fetched again.
_KEY_MAX_AGE_SECONDS = 3600
# The smallest RSA key kept from a key set, in bits (NIST SP 800-131A).
_MIN_RSA_KEY_BITS = 2048
# The shortest interval, in seconds, between key set fetches for an early refresh or after a failed fetch.
_REFETCH_INTERVAL_SECONDS = 60

_SigningKey = ECKey | OKPKey | RSAKey


class SigningAlgorithm(StrEnum):
    """Public-key signature algorithms an ID token may use, each with the key type and curves it needs.

    A token can therefore name neither ``none`` nor a shared-secret MAC.
    An algorithm with no curves listed works with a key of any size of its type.
    """

    key_type: type[_SigningKey]
    curves: tuple[str, ...]
    registry: JWSRegistry

    def __new__(cls, value: str, key_type: type[_SigningKey], curves: tuple[str, ...] = ()) -> SigningAlgorithm:
        member = str.__new__(cls, value)
        member._value_ = value
        member.key_type = key_type
        member.curves = curves
        member.registry = jws_registry([value])
        return member

    EDDSA = ("EdDSA", OKPKey, ("Ed25519", "Ed448"))
    ES256 = ("ES256", ECKey, ("P-256",))
    ES384 = ("ES384", ECKey, ("P-384",))
    ES512 = ("ES512", ECKey, ("P-521",))
    PS256 = ("PS256", RSAKey)
    PS384 = ("PS384", RSAKey)
    PS512 = ("PS512", RSAKey)
    RS256 = ("RS256", RSAKey)
    RS384 = ("RS384", RSAKey)
    RS512 = ("RS512", RSAKey)


class _RefusalReason(Enum):
    """Each member is one reason no cached key verified a token."""

    NO_KEY = auto()
    SIGNATURE = auto()


class _Refusal(NamedTuple):
    """Why no cached key verified a token, with the last key's error when one raised."""

    reason: _RefusalReason
    error: Exception | None = None


class VerifiedToken(NamedTuple):
    """The protected header and claims of a token whose signature verified, with the key that verified it."""

    header: dict[str, Any]
    claims: dict[str, Any]
    key: _SigningKey


class IssuerSigningKeys:
    """Hold one issuer's published signing keys and verify ID tokens against them.

    The keys are fetched on first use and kept for an hour.
    A token that no cached key verifies triggers an early refetch, so a rotated key is picked up.
    Early refetches happen at most once a minute, so unverifiable tokens cannot flood the issuer.
    A failed early refetch leaves a key set that is still within its hour in use.
    A stale key set whose refetch fails is not used, and the failure is reported again for a minute without a new fetch.
    A published RSA key shorter than 2048 bits is skipped, so nothing it signs verifies.
    One instance may serve sign-ins on different event loops in turn.

    NOTE: Callers must not use one instance from event loops in several threads at once, because its cache is unguarded.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        transport_factory: TransportFactory | None = None,
        algorithms: tuple[SigningAlgorithm, ...] = tuple(SigningAlgorithm),
        clock: Callable[[], float] = time.monotonic,
        token_name: str = "ID token",
    ) -> None:
        """Bind the key set to the URL it is published at.

        NOTE: Callers must check ``jwks_url`` against their own URL rule, because it is fetched as given.

        Args:
            jwks_url: The issuer's key set URL.
            transport_factory: Optional factory controlling the outbound connection for the key set fetch.
            algorithms: A tuple of the signing algorithms this issuer uses, which defaults to every accepted one.
            clock: The monotonic clock that ages the cached keys.
            token_name: What the verified tokens are called in error messages.

        Raises:
            ConfigurationError: If ``algorithms`` names no accepted algorithm or is not a tuple of them.
        """
        self._jwks_url = jwks_url
        self._transport_factory = transport_factory
        if (
            not isinstance(algorithms, tuple)
            or not algorithms
            or not all(isinstance(algorithm, SigningAlgorithm) for algorithm in algorithms)
        ):
            msg = "An issuer's signing algorithms must name one or more accepted algorithms, and nothing else"
            raise ConfigurationError(msg)
        self._algorithms = frozenset(algorithms)
        self._clock = clock
        self._keys: list[_SigningKey] = []
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._last_failure: tuple[str, FailureKind] | None = None
        self._token_name = token_name
        self._loop_lock = LoopLock()

    async def verify(self, token: str) -> VerifiedToken:
        """Return the header and claims of an ID token whose signature an issuer key verifies.

        Only the issuer's published keys are used, so a key or key URL in the token's header is ignored.

        Args:
            token: A compact signed token.

        Returns:
            The token's protected header and claims, and the published key that verified it.

        Raises:
            TokenValidationError: If the token is not a signed token, names a critical header parameter,
                names an algorithm outside the accepted list, names no published key, or fails the signature check.
            IdentityFetchError: If the key set cannot be fetched or read.
        """
        try:
            compact = parse_compact(token)
        except ValueError as exc:
            raise TokenValidationError(
                f"{self._token_name} is not a signed token", reason=TokenValidationReason.MALFORMED
            ) from exc
        header = compact.headers()
        if "crit" in header:
            # No header extension is understood here, so RFC 7515 section 4.1.11 requires refusing any listed one.
            msg = f"{self._token_name} names a critical header parameter that is not supported"
            raise TokenValidationError(msg, reason=TokenValidationReason.UNSUPPORTED)
        try:
            algorithm: SigningAlgorithm | None = SigningAlgorithm(header.get("alg"))
        except (TypeError, ValueError):
            algorithm = None
        if algorithm is None or algorithm not in self._algorithms:
            msg = f"{self._token_name} uses a signing algorithm that is not accepted"
            raise TokenValidationError(msg, reason=TokenValidationReason.UNSUPPORTED)
        try:
            algorithm.registry.check_header(header)
        except JoseError as exc:
            raise TokenValidationError(
                f"{self._token_name} header is not valid", reason=TokenValidationReason.MALFORMED
            ) from exc
        await self._refresh_if_stale()
        checked_keys = self._keys
        result = self._check_signature(compact, header.get("kid"), algorithm)
        if isinstance(result, _Refusal):
            try:
                await self._refetch_early(checked_keys)
            except IdentityFetchError:
                # The cached key set is still within its hour, so the result against it stands.
                logger.warning(
                    "The issuer's key set could not be refreshed for an unverified token, "
                    "so the cached key set stays in use"
                )
            # The token is checked again against any key set stored since its first check, by any sign-in.
            if self._keys is not checked_keys:
                result = self._check_signature(compact, header.get("kid"), algorithm)
        if isinstance(result, _Refusal):
            if result.reason is _RefusalReason.NO_KEY:
                msg = f"{self._token_name} is signed with a key the issuer does not publish"
                raise TokenValidationError(msg, reason=TokenValidationReason.UNKNOWN_KEY)
            msg = f"{self._token_name} signature did not verify"
            raise TokenValidationError(msg, reason=TokenValidationReason.SIGNATURE) from result.error
        claims = compact_claims(compact)
        if claims is None:
            msg = f"{self._token_name} claims are not a JSON object"
            raise TokenValidationError(msg, reason=TokenValidationReason.MALFORMED)
        return VerifiedToken(header, claims, result)

    def _check_signature(
        self, compact: CompactSignature, kid: object, algorithm: SigningAlgorithm
    ) -> _SigningKey | _Refusal:
        """Check a parsed token against every cached key that could have signed it.

        Args:
            compact: The parsed compact token.
            kid: The token's key ID, or ``None`` when it names none.
            algorithm: The token's signing algorithm.

        Returns:
            The key that verified the token, or why none did: no key fits it, or every candidate refused it.
            A refusal carries the last key's error, when one raised.
        """
        candidates = self._candidates(kid, algorithm)
        if not candidates:
            return _Refusal(_RefusalReason.NO_KEY)
        error: Exception | None = None
        for key in candidates:
            try:
                if jws.validate_compact(compact, key, registry=algorithm.registry):
                    return key
            except (JoseError, TypeError, ValueError) as exc:
                error = exc
        return _Refusal(_RefusalReason.SIGNATURE, error)

    def _candidates(self, kid: object, algorithm: SigningAlgorithm) -> list[_SigningKey]:
        """Return the cached keys that could have signed a token with this ``kid`` and algorithm.

        A key fits when its type and curve suit the algorithm and it names no other algorithm.
        A token without a ``kid`` is checked against every fitting key.
        A token with a ``kid`` is checked against the fitting keys with that ID.
        When no fitting key has that ID, the fitting keys published without a ``kid`` are the candidates instead.

        Args:
            kid: The token's key ID, or ``None`` when it names none.
            algorithm: The token's signing algorithm.

        Returns:
            The candidate keys, which may be empty.
        """
        fitting = [
            key
            for key in self._keys
            if isinstance(key, algorithm.key_type)
            and (not algorithm.curves or getattr(key, "curve_name", None) in algorithm.curves)
            and key.alg in (None, algorithm.value)
        ]
        if kid is None:
            return fitting
        return [key for key in fitting if key.kid == kid] or [key for key in fitting if key.kid is None]

    async def _refresh_if_stale(self) -> None:
        """Fetch the key set when it is missing or older than an hour.

        Raises:
            IdentityFetchError: If the key set cannot be fetched.
                A failure within the last minute is reported again without a new fetch.
        """
        # A fresh key set needs no lock, which keeps the lock off every ordinary sign-in.
        if self._is_younger_than(self._fetched_at, _KEY_MAX_AGE_SECONDS):
            return
        async with self._loop_lock():
            if self._is_younger_than(self._fetched_at, _KEY_MAX_AGE_SECONDS):
                return
            if self._last_failure is not None and self._is_younger_than(self._attempted_at, _REFETCH_INTERVAL_SECONDS):
                message, kind = self._last_failure
                raise IdentityFetchError(message, kind=kind)
            try:
                await self._fetch_and_store()
            except IdentityFetchError as exc:
                # Only the message and the kind are kept, so the failed request is not held until the next fetch.
                self._last_failure = (str(exc), exc.kind)
                raise

    async def _refetch_early(self, checked_keys: list[_SigningKey]) -> None:
        """Fetch the key set ahead of the hour for a token no cached key verifies, at most once a minute.

        A failure here is not recorded, because the cached key set is still within its hour.

        Args:
            checked_keys: The key set the token was checked against.
                No fetch is needed when another sign-in has replaced it since.

        Raises:
            IdentityFetchError: If the key set cannot be fetched.
        """
        async with self._loop_lock():
            if self._keys is not checked_keys or self._is_younger_than(self._attempted_at, _REFETCH_INTERVAL_SECONDS):
                return
            await self._fetch_and_store()

    async def _fetch_and_store(self) -> None:
        """Fetch the key set and keep it, recording the attempt either way.

        Raises:
            IdentityFetchError: If the key set cannot be fetched or read.
        """
        self._attempted_at = self._clock()
        self._keys = await self._fetch()
        self._fetched_at, self._last_failure = self._clock(), None

    def _is_younger_than(self, moment: float | None, seconds: int) -> bool:
        """Return whether ``moment`` is set and less than ``seconds`` ago."""
        return moment is not None and self._clock() - moment < seconds

    async def _fetch(self) -> list[_SigningKey]:
        """Fetch the key set and import every key in it that can verify a signature."""
        try:
            client = discovery_client(self._jwks_url, self._transport_factory)
        except Exception as exc:
            # The factory is caller code, so any exception from it means the connection was refused.
            msg = "Failed to fetch the issuer's signing keys: outbound connection refused"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED) from exc
        try:
            async with client:
                response = await client.get(self._jwks_url)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if 300 <= status < 400:
                msg = (
                    f"Failed to fetch the issuer's signing keys: HTTP {status}; redirects are not followed, "
                    "so set the key set URL to the canonical one"
                )
                raise IdentityFetchError(msg, kind=FailureKind.REFUSED) from exc
            status = http_failure(exc)
            msg = f"Failed to fetch the issuer's signing keys: {status.description}"
            raise IdentityFetchError(msg, kind=status.kind) from exc
        except httpx.RequestError as exc:
            transport = http_failure(exc)
            msg = f"Failed to fetch the issuer's signing keys: {transport.description}"
            raise IdentityFetchError(msg, kind=transport.kind) from exc
        except httpx.InvalidURL as exc:
            msg = "Failed to fetch the issuer's signing keys: invalid key set URL"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED) from exc
        except Exception as exc:
            # A caller's transport can raise anything, and it must still count as a failed fetch.
            # NOTE: A transport's exception can render the request it attempted, so it is chained, never logged.
            msg = "Failed to fetch the issuer's signing keys: request failed"
            raise IdentityFetchError(msg, kind=FailureKind.UNEXPECTED) from exc
        try:
            document = decode_json_body(response)
        except ValueError as exc:
            msg = "The issuer's signing keys could not be read"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED) from exc
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            msg = "The issuer's signing keys could not be read"
            raise IdentityFetchError(msg, kind=FailureKind.REFUSED)
        keys = [key for entry in entries if isinstance(entry, dict) and (key := _signing_key(entry)) is not None]
        if not keys:
            logger.warning("The issuer's key set has no key that can verify a signature")
        return keys


def _signing_key(entry: dict[str, Any]) -> _SigningKey | None:
    """Import one key set entry, or return ``None`` when it cannot verify a signature.

    RFC 7517 section 5 has a reader ignore a key it does not understand, so such an entry is skipped, not refused.

    Args:
        entry: One member of the key set's ``keys`` list.

    Returns:
        The imported public key, or ``None`` for an entry that is malformed, of another type, not for verifying,
            or an RSA key shorter than 2048 bits.
    """
    # A member written as null is read as absent, so the default applies to it and the import never sees it.
    entry = {name: value for name, value in entry.items() if value is not None}
    use = entry.get("use", "sig")
    operations = entry.get("key_ops", ["verify"])
    if use != "sig" or not isinstance(operations, list) or "verify" not in operations:
        logger.debug("Skipped a published key that is not for verifying signatures: kid=%r", entry.get("kid"))
        return None
    if entry.get("kty") not in ("EC", "OKP", "RSA"):
        logger.debug("Skipped a published key of a type that cannot verify signatures: kid=%r", entry.get("kid"))
        return None
    try:
        key = jwk.import_key(entry)
    except (JoseError, KeyError, TypeError, ValueError):
        logger.debug(
            "Skipped a published key that could not be read: kid=%r kty=%r", entry.get("kid"), entry.get("kty")
        )
        return None
    if isinstance(key, RSAKey) and key.raw_value.key_size < _MIN_RSA_KEY_BITS:
        logger.warning("Skipped a published RSA key shorter than %d bits: kid=%r", _MIN_RSA_KEY_BITS, entry.get("kid"))
        return None
    # The key types were checked above, so this only narrows the type.
    return key if isinstance(key, _SigningKey) else None
