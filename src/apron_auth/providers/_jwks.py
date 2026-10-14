"""Verify ID tokens against an issuer's published JSON Web Key Set (JWKS)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import weakref
from enum import Enum, StrEnum, auto
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx
from joserfc import jwk, jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey, OKPKey, RSAKey
from joserfc.jws import CompactSignature, JWSRegistry

from apron_auth._discovery import discovery_client
from apron_auth.errors import IdentityFetchError
from apron_auth.providers._http_errors import describe_http_error

if TYPE_CHECKING:
    from collections.abc import Callable

    from apron_auth.protocols import TransportFactory

logger = logging.getLogger(__name__)

_KEY_MAX_AGE_SECONDS = 3600
_REFETCH_INTERVAL_SECONDS = 60

_SigningKey = ECKey | OKPKey | RSAKey

# A certificate chain (``x5c``) in the header and a 8192-bit RSA signature both exceed the library's default limits.
_MAX_HEADER_LENGTH = 16384
_MAX_SIGNATURE_LENGTH = 2048


def _registry(algorithms: list[str] | None = None) -> JWSRegistry:
    """Return a registry that ignores non-critical header parameters it does not know, as RFC 7515 allows.

    Args:
        algorithms: The algorithms the registry accepts, or ``None`` for one that only parses.

    Returns:
        The registry, with size limits large enough for a certificate chain in the header.
    """
    registry = JWSRegistry(algorithms=algorithms, strict_check_header=False)
    registry.max_header_length = _MAX_HEADER_LENGTH
    registry.max_signature_length = _MAX_SIGNATURE_LENGTH
    return registry


_PARSING_REGISTRY = _registry()


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
        member.registry = _registry([value])
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


class _Outcome(Enum):
    """Each member is one outcome of checking a token against the cached keys."""

    NO_KEY = auto()
    REFUSED = auto()
    VERIFIED = auto()


class _SignatureCheck(NamedTuple):
    """The outcome of checking a token against the cached keys, with the last key's error when one refused it."""

    outcome: _Outcome
    error: Exception | None = None


class VerifiedToken(NamedTuple):
    """The protected header and claims of a token whose signature verified."""

    header: dict[str, Any]
    claims: dict[str, Any]


class IssuerSigningKeys:
    """Hold one issuer's published signing keys and verify ID tokens against them.

    The keys are fetched on first use and kept for an hour.
    A token that no cached key verifies triggers an early refetch, so a rotated key is picked up.
    Early refetches happen at most once a minute, so unverifiable tokens cannot flood the issuer.
    A failed early refetch leaves a key set that is still within its hour in use.
    A stale key set whose refetch fails is not used, and the failure is reported again for a minute without a new fetch.
    One instance may serve sign-ins on different event loops in turn.

    NOTE: Callers must not use one instance from event loops in several threads at once, because its cache is unguarded.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        transport_factory: TransportFactory | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the key set to the URL it is published at.

        NOTE: Callers must check ``jwks_url`` against their own URL rule, because it is fetched as given.

        Args:
            jwks_url: The issuer's key set URL.
            transport_factory: Optional factory controlling the outbound connection for the key set fetch.
            clock: The monotonic clock that ages the cached keys.
        """
        self._jwks_url = jwks_url
        self._transport_factory = transport_factory
        self._clock = clock
        self._keys: list[_SigningKey] = []
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._last_failure: str | None = None
        self._lock: asyncio.Lock | None = None
        self._lock_loop: weakref.ref[asyncio.AbstractEventLoop] | None = None

    async def verify(self, token: str) -> VerifiedToken:
        """Return the header and claims of an ID token whose signature an issuer key verifies.

        Only the issuer's published keys are used, so a key or key URL in the token's header is ignored.

        Args:
            token: A compact signed token.

        Returns:
            The token's protected header and its claims.

        Raises:
            IdentityFetchError: If the token is not a signed token, names a critical header parameter,
                names an algorithm outside the accepted list, names no published key, or fails the signature check.
                It is also raised if the key set cannot be fetched or read.
        """
        try:
            compact = jws.extract_compact(token.encode(), registry=_PARSING_REGISTRY)
            header = compact.headers()
        except (JoseError, RecursionError, ValueError) as exc:
            raise IdentityFetchError("ID token is not a signed token") from exc
        if not isinstance(header, dict):
            msg = "ID token is not a signed token"
            raise IdentityFetchError(msg)
        if "crit" in header:
            # No header extension is understood here, so RFC 7515 section 4.1.11 requires refusing any listed one.
            msg = "ID token names a critical header parameter that is not supported"
            raise IdentityFetchError(msg)
        try:
            algorithm = SigningAlgorithm(header.get("alg"))
        except (TypeError, ValueError) as exc:
            raise IdentityFetchError("ID token uses a signing algorithm that is not accepted") from exc
        try:
            algorithm.registry.check_header(header)
        except JoseError as exc:
            raise IdentityFetchError("ID token header is not valid") from exc
        await self._refresh_if_stale()
        checked_keys = self._keys
        check = self._check_signature(compact, header.get("kid"), algorithm)
        if check.outcome is not _Outcome.VERIFIED:
            try:
                await self._refetch_early(checked_keys)
            except IdentityFetchError as exc:
                # The cached key set is still within its hour, so the result against it stands.
                logger.warning("The issuer's key set could not be refreshed for an unverified token: %s", exc)
            # The token is checked again against any key set stored since its first check, by any sign-in.
            if self._keys is not checked_keys:
                check = self._check_signature(compact, header.get("kid"), algorithm)
        if check.outcome is _Outcome.NO_KEY:
            msg = "ID token is signed with a key the issuer does not publish"
            raise IdentityFetchError(msg)
        if check.outcome is not _Outcome.VERIFIED:
            msg = "ID token signature did not verify"
            raise IdentityFetchError(msg) from check.error
        try:
            claims = json.loads(compact.payload)
        except (RecursionError, ValueError):
            claims = None
        if not isinstance(claims, dict):
            msg = "ID token claims are not a JSON object"
            raise IdentityFetchError(msg)
        return VerifiedToken(header, claims)

    def _check_signature(self, compact: CompactSignature, kid: object, algorithm: SigningAlgorithm) -> _SignatureCheck:
        """Check a parsed token against every cached key that could have signed it.

        Args:
            compact: The parsed compact token.
            kid: The token's key ID, or ``None`` when it names none.
            algorithm: The token's signing algorithm.

        Returns:
            Whether a key verified the token, no key could have signed it, or the candidate keys refused it.
            A refusal carries the last key's error, when one raised.
        """
        candidates = self._candidates(kid, algorithm)
        if not candidates:
            return _SignatureCheck(_Outcome.NO_KEY)
        error: Exception | None = None
        for key in candidates:
            try:
                if jws.validate_compact(compact, key, registry=algorithm.registry):
                    return _SignatureCheck(_Outcome.VERIFIED)
            except (JoseError, TypeError, ValueError) as exc:
                error = exc
        return _SignatureCheck(_Outcome.REFUSED, error)

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
                raise IdentityFetchError(self._last_failure)
            try:
                await self._fetch_and_store()
            except IdentityFetchError as exc:
                # Only the domain message is kept, so the failed request's objects are not held until the next fetch.
                self._last_failure = str(exc)
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

    def _loop_lock(self) -> asyncio.Lock:
        """Return a lock for the running event loop, replacing one made for an earlier loop.

        Only the latest loop's lock is kept, so at most one finished loop stays in memory.
        """
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is None or self._lock_loop() is not loop:
            self._lock, self._lock_loop = asyncio.Lock(), weakref.ref(loop)
        return self._lock

    async def _fetch(self) -> list[_SigningKey]:
        """Fetch the key set and import every key in it that can verify a signature."""
        try:
            client = discovery_client(self._jwks_url, self._transport_factory)
        except Exception as exc:
            # The factory is caller code, so any exception from it means the connection was refused.
            raise IdentityFetchError("Failed to fetch the issuer's signing keys: outbound connection refused") from exc
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
                raise IdentityFetchError(msg) from exc
            raise IdentityFetchError(f"Failed to fetch the issuer's signing keys: {describe_http_error(exc)}") from exc
        except httpx.RequestError as exc:
            raise IdentityFetchError(f"Failed to fetch the issuer's signing keys: {describe_http_error(exc)}") from exc
        except httpx.InvalidURL as exc:
            raise IdentityFetchError("Failed to fetch the issuer's signing keys: invalid key set URL") from exc
        except Exception as exc:
            # A caller's transport can raise anything, and it must still count as a failed fetch.
            logger.debug("The issuer's key set request failed unexpectedly", exc_info=exc)
            raise IdentityFetchError("Failed to fetch the issuer's signing keys: request failed") from exc
        try:
            document = response.json()
        except (RecursionError, ValueError) as exc:
            raise IdentityFetchError("The issuer's signing keys could not be read") from exc
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            msg = "The issuer's signing keys could not be read"
            raise IdentityFetchError(msg)
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
        The imported public key, or ``None`` for an entry that is malformed, of another type, or not for verifying.
    """
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
    # The key types were checked above, so this only narrows the type.
    return key if isinstance(key, _SigningKey) else None
