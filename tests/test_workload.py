from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pytest
from joserfc import jwk, jws
from joserfc.jws import JWSRegistry
from pytest_httpx import HTTPXMock

from apron_auth.errors import ConfigurationError, IdentityFetchError, TokenExpiredError, TokenVerificationError
from apron_auth.workload import WorkloadTokenVerifier

ISSUER = "https://token.actions.example.com"
DOCUMENT_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/.well-known/jwks"
AUDIENCE = "https://gateway.example.com"
RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})


def published(*keys: Any) -> dict[str, Any]:
    """Return a key set document holding the public half of each key."""
    return {"keys": [key.as_dict(private=False) for key in keys]}


def claims(**overrides: Any) -> dict[str, Any]:
    """Return the claims of a valid workload token, with ``overrides`` applied and ``None`` values dropped."""
    now = int(time.time())
    base = {"iss": ISSUER, "sub": "repo:acme/app", "aud": AUDIENCE, "iat": now, "exp": now + 300}
    return {name: value for name, value in {**base, **overrides}.items() if value is not None}


def signed(payload: dict[str, Any], key: Any = RSA_KEY) -> str:
    """Return a compact RS256 token over ``payload``, signed with ``key``."""
    registry = JWSRegistry(algorithms=["RS256"])
    return jws.serialize_compact({"alg": "RS256", "kid": key.kid}, json.dumps(payload).encode(), key, registry=registry)


class FakeClock:
    """A monotonic clock a test moves forward by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def discoverable(httpx_mock: HTTPXMock, *keys: Any) -> None:
    """Publish a configuration document with no authorization endpoint, as workload issuers do, and its key set."""
    httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URL})
    httpx_mock.add_response(url=JWKS_URL, json=published(*(keys or (RSA_KEY,))))


class TestVerify:
    """Test that a workload token is trusted only when its signature and claims verify."""

    async def test_returns_the_identity_of_a_good_token(self, httpx_mock: HTTPXMock) -> None:
        """An issuer with no authorization endpoint is discovered, and its token's identity is returned."""
        discoverable(httpx_mock)
        payload = claims()

        identity = await WorkloadTokenVerifier(ISSUER).verify(signed(payload), audience=AUDIENCE)

        assert identity.issuer == ISSUER
        assert identity.subject == "repo:acme/app"
        assert identity.audiences == (AUDIENCE,)
        assert identity.expires_at == payload["exp"]
        assert identity.email is None
        assert identity.claims == payload

    async def test_a_configured_key_set_skips_discovery(self, httpx_mock: HTTPXMock) -> None:
        """A ``jwks_url`` is used as given, so no configuration document is fetched."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))

        identity = await WorkloadTokenVerifier(ISSUER, jwks_url=JWKS_URL).verify(signed(claims()), audience=AUDIENCE)

        assert identity.subject == "repo:acme/app"

    @pytest.mark.parametrize(
        ("email_verified", "expected"),
        [(True, "bot@acme.iam.example.com"), ("true", None), (False, None), (None, None)],
    )
    async def test_an_email_counts_only_when_marked_verified(
        self, httpx_mock: HTTPXMock, email_verified: object, expected: str | None
    ) -> None:
        """Only the boolean ``true`` verifies an address, so a string ``"true"`` does not."""
        discoverable(httpx_mock)
        token = signed(claims(email="bot@acme.iam.example.com", email_verified=email_verified))

        identity = await WorkloadTokenVerifier(ISSUER).verify(token, audience=AUDIENCE)

        assert identity.email == expected

    async def test_one_of_several_audiences_is_enough(self, httpx_mock: HTTPXMock) -> None:
        """A token naming several audiences verifies when one of them is accepted."""
        discoverable(httpx_mock)
        token = signed(claims(aud=["https://other.example.com", AUDIENCE]))

        identity = await WorkloadTokenVerifier(ISSUER).verify(token, audience=["https://third.example.com", AUDIENCE])

        assert identity.audiences == ("https://other.example.com", AUDIENCE)

    async def test_concurrent_first_calls_share_one_discovery(self, httpx_mock: HTTPXMock) -> None:
        """Calls that arrive before the first discovery finishes wait for it, so each document is fetched once."""
        discoverable(httpx_mock)
        verifier = WorkloadTokenVerifier(ISSUER)
        token = signed(claims())

        identities = await asyncio.gather(*(verifier.verify(token, audience=AUDIENCE) for _ in range(5)))

        assert len(identities) == 5
        assert len(httpx_mock.get_requests(url=DOCUMENT_URL)) == 1
        assert len(httpx_mock.get_requests(url=JWKS_URL)) == 1

    async def test_no_audience_leaves_the_match_to_the_caller(self, httpx_mock: HTTPXMock) -> None:
        """``audience=None`` accepts any audience, and returns it for the caller to match."""
        discoverable(httpx_mock)

        identity = await WorkloadTokenVerifier(ISSUER).verify(signed(claims(aud="anything")), audience=None)

        assert identity.audiences == ("anything",)


class TestRefusals:
    """Test that a token is refused, as a refusal rather than an outage, for each reason it cannot be trusted."""

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(claims(aud="https://other.example.com"), id="another audience"),
            pytest.param(claims(iss="https://other.example.com"), id="another issuer"),
            pytest.param(claims(iss=[ISSUER]), id="issuer as a list"),
            pytest.param(claims(sub=None), id="no subject"),
            pytest.param(claims(sub=""), id="empty subject"),
            pytest.param(claims(aud=None), id="no audience"),
            pytest.param(claims(iat=None), id="no issued-at"),
            pytest.param(claims(exp=None), id="no expiry"),
            pytest.param(claims(exp="soon"), id="expiry not a number"),
            pytest.param(claims(nbf=int(time.time()) + 3600), id="not yet valid"),
            pytest.param(claims(iat=int(time.time()) + 3600), id="issued in the future"),
        ],
    )
    async def test_claims_that_do_not_validate(self, httpx_mock: HTTPXMock, payload: dict[str, Any]) -> None:
        """A signature that verifies does not save a token whose claims do not."""
        discoverable(httpx_mock)

        with pytest.raises(TokenVerificationError, match="claims did not validate"):
            await WorkloadTokenVerifier(ISSUER).verify(signed(payload), audience=AUDIENCE)

    async def test_an_expired_token(self, httpx_mock: HTTPXMock) -> None:
        """An expired token raises its own refusal, so the caller can say to fetch a fresh one."""
        discoverable(httpx_mock)
        now = int(time.time())

        with pytest.raises(TokenExpiredError):
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims(iat=now - 900, exp=now - 600)), audience=AUDIENCE)

    async def test_a_token_signed_by_another_key(self, httpx_mock: HTTPXMock) -> None:
        """A key the issuer does not publish verifies nothing."""
        discoverable(httpx_mock)
        stranger = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})

        with pytest.raises(TokenVerificationError, match="signature did not verify"):
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims(), stranger), audience=AUDIENCE)

    @pytest.mark.filterwarnings("ignore:Key size should be:joserfc.errors.SecurityWarning")
    async def test_a_short_rsa_key(self, httpx_mock: HTTPXMock) -> None:
        """A key shorter than 2048 bits is never used, even when the issuer publishes it."""
        short_key = jwk.RSAKey.generate_key(1024, parameters={"kid": "rsa-short"}, auto_kid=False)
        discoverable(httpx_mock, short_key)

        with pytest.raises(TokenVerificationError, match="^Workload token is signed with a key the issuer does not"):
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims(), short_key), audience=AUDIENCE)

    async def test_an_oversized_token_is_refused_before_any_fetch(self) -> None:
        """A token longer than any issuer signs is refused without contacting the issuer."""
        with pytest.raises(TokenVerificationError, match="longer than"):
            await WorkloadTokenVerifier(ISSUER).verify("a" * 20000, audience=AUDIENCE)

    async def test_a_token_that_is_not_signed(self, httpx_mock: HTTPXMock) -> None:
        """Text that is not a compact signed token is refused before discovery, so not as an outage."""
        with pytest.raises(TokenVerificationError, match="^Workload token is not a signed token"):
            await WorkloadTokenVerifier(ISSUER).verify("not-a-token", audience=AUDIENCE)

        assert not httpx_mock.get_requests()

    async def test_a_token_that_is_not_signed_during_an_outage(self, httpx_mock: HTTPXMock) -> None:
        """A malformed token is refused even while the issuer cannot be reached."""
        clock = FakeClock()
        verifier = WorkloadTokenVerifier(ISSUER, clock=clock)
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=503)
        with pytest.raises(IdentityFetchError, match="HTTP 503"):
            await verifier.verify(signed(claims()), audience=AUDIENCE)

        with pytest.raises(TokenVerificationError, match="not a signed token"):
            await verifier.verify("not-a-token", audience=AUDIENCE)


class TestOutages:
    """Test that an issuer that cannot be reached is reported as an outage, not as a refused token."""

    async def test_a_document_for_another_issuer(self, httpx_mock: HTTPXMock) -> None:
        """A configuration document naming another issuer is not used."""
        httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": "https://other.example.com", "jwks_uri": JWKS_URL})

        with pytest.raises(IdentityFetchError) as caught:
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims()), audience=AUDIENCE)

        assert not isinstance(caught.value, TokenVerificationError)

    async def test_a_document_without_a_key_set(self, httpx_mock: HTTPXMock) -> None:
        """A configuration document that names no key set cannot verify anything."""
        httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": ISSUER})

        with pytest.raises(IdentityFetchError, match="names no signing key set"):
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims()), audience=AUDIENCE)

    async def test_a_failed_discovery_is_retried_after_a_minute(self, httpx_mock: HTTPXMock) -> None:
        """A failed discovery is reported again for a minute without a new fetch, then tried again."""
        clock = FakeClock()
        verifier = WorkloadTokenVerifier(ISSUER, clock=clock)
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=503)
        token = signed(claims())

        for _ in range(2):
            with pytest.raises(IdentityFetchError, match="HTTP 503"):
                await verifier.verify(token, audience=AUDIENCE)
        clock.now += 61
        discoverable(httpx_mock)

        identity = await verifier.verify(token, audience=AUDIENCE)

        assert identity.subject == "repo:acme/app"
        assert len(httpx_mock.get_requests(url=DOCUMENT_URL)) == 2

    async def test_an_unreachable_key_set(self, httpx_mock: HTTPXMock) -> None:
        """A key set that cannot be fetched is an outage, not a refusal."""
        httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URL})
        httpx_mock.add_response(url=JWKS_URL, status_code=500)

        with pytest.raises(IdentityFetchError) as caught:
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims()), audience=AUDIENCE)

        assert not isinstance(caught.value, TokenVerificationError)


class TestConfiguration:
    """Test that a verifier refuses URLs it could not safely fetch from, and audiences that would accept anything."""

    @pytest.mark.parametrize(
        "audience",
        [
            pytest.param([], id="empty list"),
            pytest.param((), id="empty tuple"),
            pytest.param("", id="empty string"),
            pytest.param([AUDIENCE, ""], id="an empty member"),
            pytest.param([AUDIENCE, 1], id="a member that is not a string"),
        ],
    )
    async def test_an_audience_that_names_nothing(self, audience: Any) -> None:
        """An empty audience would accept a token minted for any service, so it is refused before any fetch."""
        with pytest.raises(ConfigurationError, match="or be None"):
            await WorkloadTokenVerifier(ISSUER).verify(signed(claims()), audience=audience)

    @pytest.mark.parametrize(
        ("issuer", "jwks_url"),
        [
            pytest.param("http://token.actions.example.com", None, id="http issuer"),
            pytest.param("https://token.actions.example.com?tenant=1", None, id="issuer with a query"),
            pytest.param(ISSUER, "http://token.actions.example.com/jwks", id="http key set"),
        ],
    )
    def test_an_unacceptable_url(self, issuer: str, jwks_url: str | None) -> None:
        """An ``http`` URL, or an issuer with a query, is a configuration error."""
        with pytest.raises(ConfigurationError):
            WorkloadTokenVerifier(issuer, jwks_url=jwks_url)

    def test_http_is_allowed_for_local_development(self) -> None:
        """``allow_insecure_http`` lets an ``http`` issuer through."""
        verifier = WorkloadTokenVerifier("http://localhost:8080", allow_insecure_http=True)

        assert verifier.issuer == "http://localhost:8080"
