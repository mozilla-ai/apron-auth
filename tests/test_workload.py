from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
from joserfc import jwk, jws
from joserfc.jws import JWSRegistry
from pytest_httpx import HTTPXMock

from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    TokenExpiredError,
    TokenValidationError,
    TokenValidationReason,
)
from apron_auth.models import TimeoutPolicy, UrlField, WorkloadIssuer
from apron_auth.workload import WorkloadTokenVerifier

ISSUER = "https://token.actions.example.com"
DOCUMENT_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/.well-known/jwks"
AUDIENCE = "https://gateway.example.com"
RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})

OTHER_ISSUER = "https://oidc.cluster.example.com"
OTHER_DOCUMENT_URL = f"{OTHER_ISSUER}/.well-known/openid-configuration"
OTHER_JWKS_URL = f"{OTHER_ISSUER}/.well-known/jwks"
OTHER_RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-2"})


def trusting(*issuers: WorkloadIssuer, **options: Any) -> WorkloadTokenVerifier:
    """Return a verifier accepting ``issuers``, or the one test issuer when none are named."""
    return WorkloadTokenVerifier(issuers or (WorkloadIssuer(issuer=ISSUER),), **options)


def published(*keys: Any) -> dict[str, Any]:
    """Return a key set document holding the public half of each key."""
    return {"keys": [key.as_dict(private=False) for key in keys]}


def claims(**overrides: Any) -> dict[str, Any]:
    """Return the claims of a valid workload token, with ``overrides`` applied and ``None`` values dropped."""
    now = int(time.time())
    base = {"iss": ISSUER, "sub": "repo:acme/app", "aud": AUDIENCE, "iat": now, "exp": now + 300}
    return {name: value for name, value in {**base, **overrides}.items() if value is not None}


def signed_text(payload: bytes, key: Any = RSA_KEY) -> str:
    """Return a compact RS256 token over ``payload`` as written, so its JSON text reaches the reader unchanged."""
    registry = JWSRegistry(algorithms=["RS256"])
    return jws.serialize_compact({"alg": "RS256", "kid": key.kid}, payload, key, registry=registry)


def signed(payload: dict[str, Any], key: Any = RSA_KEY) -> str:
    """Return a compact RS256 token over ``payload``, signed with ``key``."""
    return signed_text(json.dumps(payload).encode(), key)


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


def other_discoverable(httpx_mock: HTTPXMock, *keys: Any) -> None:
    """Publish the second test issuer's configuration document and key set."""
    httpx_mock.add_response(url=OTHER_DOCUMENT_URL, json={"issuer": OTHER_ISSUER, "jwks_uri": OTHER_JWKS_URL})
    httpx_mock.add_response(url=OTHER_JWKS_URL, json=published(*(keys or (OTHER_RSA_KEY,))))


class TestVerify:
    """Test that a workload token is trusted only when its signature and claims verify."""

    async def test_returns_the_identity_of_a_good_token(self, httpx_mock: HTTPXMock) -> None:
        """An issuer with no authorization endpoint is discovered, and its token's identity is returned."""
        discoverable(httpx_mock)
        payload = claims()

        identity = await trusting().verify(signed(payload), audience=AUDIENCE)

        assert identity.issuer == ISSUER
        assert identity.subject == "repo:acme/app"
        assert identity.audiences == (AUDIENCE,)
        assert identity.expires_at == payload["exp"]
        assert identity.email is None
        assert identity.claims == payload

    async def test_a_configured_key_set_skips_discovery(self, httpx_mock: HTTPXMock) -> None:
        """A ``jwks_url`` is used as given, so no configuration document is fetched."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))

        identity = await trusting(WorkloadIssuer(issuer=ISSUER, jwks_url=JWKS_URL)).verify(
            signed(claims()), audience=AUDIENCE
        )

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

        identity = await trusting().verify(token, audience=AUDIENCE)

        assert identity.email == expected

    async def test_one_of_several_audiences_is_enough(self, httpx_mock: HTTPXMock) -> None:
        """A token naming several audiences verifies when one of them is accepted."""
        discoverable(httpx_mock)
        token = signed(claims(aud=["https://other.example.com", AUDIENCE]))

        identity = await trusting().verify(token, audience=["https://third.example.com", AUDIENCE])

        assert identity.audiences == ("https://other.example.com", AUDIENCE)

    async def test_concurrent_first_calls_share_one_discovery(self, httpx_mock: HTTPXMock) -> None:
        """Calls that arrive before the first discovery finishes wait for it, so each document is fetched once."""
        discoverable(httpx_mock)
        verifier = trusting()
        token = signed(claims())

        identities = await asyncio.gather(*(verifier.verify(token, audience=AUDIENCE) for _ in range(5)))

        assert len(identities) == 5
        assert len(httpx_mock.get_requests(url=DOCUMENT_URL)) == 1
        assert len(httpx_mock.get_requests(url=JWKS_URL)) == 1

    async def test_no_audience_leaves_the_match_to_the_caller(self, httpx_mock: HTTPXMock) -> None:
        """``audience=None`` accepts any audience, and returns it for the caller to match."""
        discoverable(httpx_mock)

        identity = await trusting().verify(signed(claims(aud="anything")), audience=None)

        assert identity.audiences == ("anything",)


class TestIssuerRouting:
    """Test that a token is checked against the keys of the issuer it names, and of no other."""

    async def test_a_token_is_checked_against_the_issuer_that_signed_it(self, httpx_mock: HTTPXMock) -> None:
        """Each accepted issuer publishes its own keys, so a verifier serves several platforms at once."""
        discoverable(httpx_mock)
        other_discoverable(httpx_mock)
        trusting_both = trusting(WorkloadIssuer(issuer=ISSUER), WorkloadIssuer(issuer=OTHER_ISSUER))

        first = await trusting_both.verify(signed(claims()), audience=AUDIENCE)
        second = await trusting_both.verify(signed(claims(iss=OTHER_ISSUER), OTHER_RSA_KEY), audience=AUDIENCE)

        assert first.issuer == ISSUER
        assert second.issuer == OTHER_ISSUER

    async def test_another_trusted_issuers_key_verifies_nothing(self, httpx_mock: HTTPXMock) -> None:
        """Accepting two issuers does not pool their keys, so neither can sign for the other."""
        other_discoverable(httpx_mock)
        trusting_both = trusting(WorkloadIssuer(issuer=ISSUER), WorkloadIssuer(issuer=OTHER_ISSUER))

        with pytest.raises(TokenValidationError, match="key the issuer does not publish") as exc_info:
            await trusting_both.verify(signed(claims(iss=OTHER_ISSUER), RSA_KEY), audience=AUDIENCE)

        assert exc_info.value.reason is TokenValidationReason.UNKNOWN_KEY
        assert not httpx_mock.get_requests(url=DOCUMENT_URL)

    async def test_a_key_reusing_another_issuers_key_id_verifies_nothing(self, httpx_mock: HTTPXMock) -> None:
        """The key ID selects a candidate and proves nothing, so one reused from elsewhere still fails the check."""
        other_discoverable(httpx_mock)
        impostor = jwk.RSAKey.generate_key(2048, parameters={"kid": OTHER_RSA_KEY.kid})
        trusting_both = trusting(WorkloadIssuer(issuer=ISSUER), WorkloadIssuer(issuer=OTHER_ISSUER))

        with pytest.raises(TokenValidationError, match="signature did not verify") as exc_info:
            await trusting_both.verify(signed(claims(iss=OTHER_ISSUER), impostor), audience=AUDIENCE)

        assert exc_info.value.reason is TokenValidationReason.SIGNATURE

    @pytest.mark.parametrize(
        "issuer_claim",
        [
            pytest.param("https://evil.example.com", id="another issuer"),
            pytest.param(None, id="no issuer"),
            pytest.param([ISSUER], id="issuer as a list"),
            pytest.param("", id="empty issuer"),
        ],
    )
    async def test_an_issuer_it_does_not_accept_is_refused_before_any_fetch(
        self, httpx_mock: HTTPXMock, issuer_claim: object
    ) -> None:
        """Selecting the key set on the unverified claim means an issuer named by no entry is refused first."""
        with pytest.raises(TokenValidationError, match="names an issuer") as exc_info:
            await trusting().verify(signed(claims(iss=issuer_claim)), audience=AUDIENCE)

        assert exc_info.value.reason is TokenValidationReason.UNKNOWN_ISSUER
        assert not httpx_mock.get_requests()

    async def test_one_issuers_outage_leaves_another_token_verifiable(self, httpx_mock: HTTPXMock) -> None:
        """Each issuer keeps its own discovery state, so one that is unreachable refuses only its own tokens."""
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=503)
        other_discoverable(httpx_mock)
        trusting_both = trusting(WorkloadIssuer(issuer=ISSUER), WorkloadIssuer(issuer=OTHER_ISSUER))

        with pytest.raises(IdentityFetchError, match="HTTP 503"):
            await trusting_both.verify(signed(claims()), audience=AUDIENCE)
        identity = await trusting_both.verify(signed(claims(iss=OTHER_ISSUER), OTHER_RSA_KEY), audience=AUDIENCE)

        assert identity.issuer == OTHER_ISSUER

    def test_the_issuers_it_accepts_are_readable(self) -> None:
        trusting_both = trusting(WorkloadIssuer(issuer=ISSUER), WorkloadIssuer(issuer=OTHER_ISSUER))

        assert trusting_both.issuers == (ISSUER, OTHER_ISSUER)


class TestRefusals:
    """Test that a token is refused, as a refusal rather than an outage, for each reason it cannot be trusted."""

    @pytest.mark.parametrize(
        ("payload", "reason"),
        [
            pytest.param(
                claims(aud="https://other.example.com"), TokenValidationReason.AUDIENCE, id="another audience"
            ),
            pytest.param(claims(sub=None), TokenValidationReason.CLAIMS, id="no subject"),
            pytest.param(claims(sub=""), TokenValidationReason.CLAIMS, id="empty subject"),
            pytest.param(claims(aud=None), TokenValidationReason.AUDIENCE, id="no audience"),
            pytest.param(claims(iat=None), TokenValidationReason.CLAIMS, id="no issued-at"),
            pytest.param(claims(exp=None), TokenValidationReason.CLAIMS, id="no expiry"),
            pytest.param(claims(exp="soon"), TokenValidationReason.CLAIMS, id="expiry not a number"),
            pytest.param(claims(nbf=int(time.time()) + 3600), TokenValidationReason.CLAIMS, id="not yet valid"),
            pytest.param(claims(iat=int(time.time()) + 3600), TokenValidationReason.CLAIMS, id="issued in the future"),
        ],
    )
    async def test_claims_that_do_not_validate(
        self, httpx_mock: HTTPXMock, payload: dict[str, Any], reason: TokenValidationReason
    ) -> None:
        """A signature that verifies does not save a token whose claims do not."""
        discoverable(httpx_mock)

        with pytest.raises(TokenValidationError, match="claims did not validate") as exc_info:
            await trusting().verify(signed(payload), audience=AUDIENCE)
        assert exc_info.value.reason is reason

    @pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity"])
    async def test_claims_naming_a_json_constant(self, httpx_mock: HTTPXMock, literal: bytes) -> None:
        """RFC 8259 defines no such literal, so claims naming one cannot be read, and name no issuer either."""
        token = signed_text(b'{"iss":"' + ISSUER.encode() + b'","sub":"s","aud":"a","iat":1,"exp":' + literal + b"}")

        with pytest.raises(TokenValidationError, match="claims are not a JSON object") as exc_info:
            await trusting().verify(token, audience="a")

        assert exc_info.value.reason is TokenValidationReason.MALFORMED
        assert not httpx_mock.get_requests()

    async def test_an_expiry_that_overflows_a_float(self, httpx_mock: HTTPXMock) -> None:
        """An overflowing exponent is valid JSON that reads as infinity, which compares false against every time."""
        discoverable(httpx_mock)
        token = signed_text(b'{"iss":"' + ISSUER.encode() + b'","sub":"s","aud":"a","iat":1,"exp":1e400}')

        with pytest.raises(TokenValidationError, match="claims did not validate") as exc_info:
            await trusting().verify(token, audience="a")
        assert exc_info.value.reason is TokenValidationReason.CLAIMS

    async def test_an_expired_token(self, httpx_mock: HTTPXMock) -> None:
        """An expired token raises its own refusal, so the caller can say to fetch a fresh one."""
        discoverable(httpx_mock)
        now = int(time.time())

        with pytest.raises(TokenExpiredError) as exc_info:
            await trusting().verify(signed(claims(iat=now - 900, exp=now - 600)), audience=AUDIENCE)
        assert exc_info.value.reason is TokenValidationReason.EXPIRED

    async def test_a_token_signed_by_another_key(self, httpx_mock: HTTPXMock) -> None:
        """A key the issuer does not publish verifies nothing."""
        discoverable(httpx_mock)
        stranger = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})

        with pytest.raises(TokenValidationError, match="signature did not verify") as exc_info:
            await trusting().verify(signed(claims(), stranger), audience=AUDIENCE)
        assert exc_info.value.reason is TokenValidationReason.SIGNATURE

    @pytest.mark.filterwarnings("ignore:Key size should be:joserfc.errors.SecurityWarning")
    async def test_a_short_rsa_key(self, httpx_mock: HTTPXMock) -> None:
        """A key shorter than 2048 bits is never used, even when the issuer publishes it."""
        short_key = jwk.RSAKey.generate_key(1024, parameters={"kid": "rsa-short"}, auto_kid=False)
        discoverable(httpx_mock, short_key)

        with pytest.raises(
            TokenValidationError, match="^The token is signed with a key the issuer does not"
        ) as exc_info:
            await trusting().verify(signed(claims(), short_key), audience=AUDIENCE)
        assert exc_info.value.reason is TokenValidationReason.UNKNOWN_KEY

    async def test_an_oversized_token_is_refused_before_any_fetch(self) -> None:
        """A token longer than any issuer signs is refused without contacting the issuer."""
        with pytest.raises(TokenValidationError, match="longer than") as exc_info:
            await trusting().verify("a" * 20000, audience=AUDIENCE)
        assert exc_info.value.reason is TokenValidationReason.MALFORMED

    async def test_a_token_that_is_not_signed(self, httpx_mock: HTTPXMock) -> None:
        """Text that is not a compact signed token is refused before discovery, so not as an outage."""
        with pytest.raises(TokenValidationError, match="^Workload token is not a compact signed token") as exc_info:
            await trusting().verify("not-a-token", audience=AUDIENCE)
        assert exc_info.value.reason is TokenValidationReason.MALFORMED

        assert not httpx_mock.get_requests()

    async def test_a_token_that_is_not_signed_during_an_outage(self, httpx_mock: HTTPXMock) -> None:
        """A malformed token is refused even while the issuer cannot be reached."""
        clock = FakeClock()
        verifier = trusting(clock=clock)
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=503)
        with pytest.raises(IdentityFetchError, match="HTTP 503"):
            await verifier.verify(signed(claims()), audience=AUDIENCE)

        with pytest.raises(TokenValidationError, match="not a compact signed token"):
            await verifier.verify("not-a-token", audience=AUDIENCE)


class TestOutages:
    """Test that an issuer that cannot be reached is reported as an outage, not as a refused token."""

    async def test_a_document_for_another_issuer(self, httpx_mock: HTTPXMock) -> None:
        """A configuration document naming another issuer is not used."""
        httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": "https://other.example.com", "jwks_uri": JWKS_URL})

        with pytest.raises(IdentityFetchError, match="declares a different issuer") as caught:
            await trusting().verify(signed(claims()), audience=AUDIENCE)

        assert not isinstance(caught.value, TokenValidationError)
        assert caught.value.kind is FailureKind.REFUSED

    async def test_a_document_without_a_key_set(self, httpx_mock: HTTPXMock) -> None:
        """A configuration document that names no key set cannot verify anything."""
        httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": ISSUER})

        with pytest.raises(IdentityFetchError, match="names no signing key set"):
            await trusting().verify(signed(claims()), audience=AUDIENCE)

    async def test_a_failed_discovery_is_retried_after_a_minute(self, httpx_mock: HTTPXMock) -> None:
        """A failed discovery is reported again for a minute without a new fetch, then tried again."""
        clock = FakeClock()
        verifier = trusting(clock=clock)
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

    async def test_a_cached_discovery_failure_holds_no_exception_object(self, httpx_mock: HTTPXMock) -> None:
        """Between attempts only the message and the kind are kept, not a traceback that reaches the token."""
        verifier = trusting(clock=FakeClock())
        httpx_mock.add_response(url=DOCUMENT_URL, status_code=503)

        with pytest.raises(IdentityFetchError):
            await verifier.verify(signed(claims()), audience=AUDIENCE)

        assert not isinstance(verifier._issuers[ISSUER]._discovery_failure, BaseException)

    async def test_an_unreachable_key_set(self, httpx_mock: HTTPXMock) -> None:
        """A key set that cannot be fetched is an outage, not a refusal."""
        httpx_mock.add_response(url=DOCUMENT_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URL})
        httpx_mock.add_response(url=JWKS_URL, status_code=500)

        with pytest.raises(IdentityFetchError) as caught:
            await trusting().verify(signed(claims()), audience=AUDIENCE)

        assert not isinstance(caught.value, TokenValidationError)


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
            await trusting().verify(signed(claims()), audience=audience)

    def test_an_issuer_with_a_query_is_refused(self) -> None:
        """OpenID Connect Discovery 1.0 section 4.1 gives an issuer no query, so one with a query names none."""
        with pytest.raises(ConfigurationError):
            trusting(WorkloadIssuer(issuer="https://token.actions.example.com?tenant=1"))

    def test_accepting_no_issuer_is_refused(self) -> None:
        """A verifier that accepts no issuer can verify nothing, so it is refused where it is built."""
        with pytest.raises(ConfigurationError, match="one or more issuers"):
            WorkloadTokenVerifier([])

    @pytest.mark.parametrize(
        "issuers",
        [
            pytest.param(ISSUER, id="one issuer as a string"),
            pytest.param([ISSUER], id="a list of strings"),
            pytest.param([WorkloadIssuer(issuer=ISSUER), ISSUER], id="a list with a string among the issuers"),
        ],
    )
    def test_something_that_is_not_an_issuer_is_refused(self, issuers: Any) -> None:
        """A bare string carries no key set and no transport rule, so the typed value is required."""
        with pytest.raises(ConfigurationError, match="one or more issuers"):
            WorkloadTokenVerifier(issuers)

    def test_one_issuer_named_twice_is_refused(self) -> None:
        """Two entries for one issuer leave it unsaid which key set its tokens are checked against."""
        with pytest.raises(ConfigurationError, match="named more than once"):
            WorkloadTokenVerifier([WorkloadIssuer(issuer=ISSUER), WorkloadIssuer(issuer=ISSUER, jwks_url=JWKS_URL)])

    def test_a_loopback_issuer_is_accepted_for_local_development(self) -> None:
        """A request to the loopback interface reaches no network, so plain http there needs no waiver."""
        local = trusting(WorkloadIssuer(issuer="http://localhost:8080"))

        assert local.issuers == ("http://localhost:8080",)

    def test_an_issuer_waived_in_code_is_accepted_for_local_development(self) -> None:
        """A development issuer that is not loopback is reached through the waiver, and through nothing else."""
        waived = WorkloadIssuer.unsafe.allow_plain_http(UrlField.ISSUER, issuer="http://keycloak:8080")

        assert trusting(waived).issuers == ("http://keycloak:8080",)


class TestTheTimeoutPolicyBoundsDiscovery:
    async def test_a_document_that_never_lands_is_refused_as_a_timeout(self) -> None:
        async def crawl(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(5)
            return httpx.Response(200, json={})

        verifier = trusting(
            transport_factory=lambda url: httpx.MockTransport(crawl),
            timeouts=TimeoutPolicy(connect_seconds=0.05, request_seconds=0.05),
        )

        with pytest.raises(IdentityFetchError) as refusal:
            await verifier.verify(signed(claims()), audience=AUDIENCE)

        assert refusal.value.kind is FailureKind.TIMEOUT
