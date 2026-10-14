from __future__ import annotations

import asyncio
import base64
import gc
import json
import logging
import weakref
from typing import Any

import httpx
import pytest
from joserfc import jwk, jws
from joserfc.jws import JWSRegistry
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.providers._jwks import IssuerSigningKeys

JWKS_URL = "https://sso.example.com/realms/acme/protocol/openid-connect/certs"
RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})
OTHER_RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-2"})
EC_KEY = jwk.ECKey.generate_key("P-256", parameters={"kid": "ec-1"})
OKP_KEY = jwk.OKPKey.generate_key("Ed25519", parameters={"kid": "okp-1"})


def published(*keys: Any) -> dict[str, Any]:
    """Return a key set document holding the public half of each key."""
    return {"keys": [key.as_dict(private=False) for key in keys]}


def signed(key: Any, *, alg: str = "RS256", claims: dict[str, Any] | None = None, **header: Any) -> str:
    """Return a compact token signed with ``key``, with ``kid`` taken from the key unless given."""
    header = {"alg": alg, "kid": key.kid, **header}
    header = {name: value for name, value in header.items() if value is not None}
    registry = JWSRegistry(algorithms=[alg], strict_check_header=False)
    return jws.serialize_compact(header, json.dumps(claims or {"sub": "u-1"}).encode(), key, registry=registry)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeClock:
    """A monotonic clock a test moves forward by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestVerify:
    """Test that a token is trusted only when an issuer key verifies it."""

    async def test_returns_the_header_and_claims_of_a_good_token(self, httpx_mock: HTTPXMock) -> None:
        """A token signed by a published key verifies."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

        assert verified.header["kid"] == "rsa-1"
        assert verified.claims == {"sub": "u-1"}

    @pytest.mark.filterwarnings("ignore:EdDSA is deprecated:joserfc.errors.SecurityWarning")
    async def test_accepts_an_eddsa_key(self, httpx_mock: HTTPXMock) -> None:
        """An Edwards-curve key verifies as well as RSA and EC keys."""
        httpx_mock.add_response(url=JWKS_URL, json=published(OKP_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(OKP_KEY, alg="EdDSA"))

        assert verified.claims == {"sub": "u-1"}

    async def test_a_token_without_a_kid_picks_the_key_on_its_curve(self, httpx_mock: HTTPXMock) -> None:
        """Two EC keys on different curves do not make a token without a ``kid`` ambiguous."""
        p384_key = jwk.ECKey.generate_key("P-384", parameters={"kid": "ec-384"})
        httpx_mock.add_response(url=JWKS_URL, json=published(EC_KEY, p384_key))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(EC_KEY, alg="ES256", kid=None))

        assert verified.claims == {"sub": "u-1"}

    @pytest.mark.filterwarnings("ignore:EdDSA is deprecated:joserfc.errors.SecurityWarning")
    async def test_a_key_agreement_curve_does_not_fit_eddsa(self, httpx_mock: HTTPXMock) -> None:
        """An X25519 key cannot sign, so it does not make an EdDSA token without a ``kid`` ambiguous."""
        exchange_key = jwk.OKPKey.generate_key("X25519", parameters={"kid": "x-1"})
        httpx_mock.add_response(url=JWKS_URL, json=published(OKP_KEY, exchange_key))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(OKP_KEY, alg="EdDSA", kid=None))

        assert verified.claims == {"sub": "u-1"}

    async def test_a_token_kid_matches_the_only_key_without_a_kid(self, httpx_mock: HTTPXMock) -> None:
        """An issuer that publishes its key without a ``kid`` can still name one in its tokens."""
        document = published(RSA_KEY)
        del document["keys"][0]["kid"]
        httpx_mock.add_response(url=JWKS_URL, json=document)

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY, kid="k1"))

        assert verified.claims == {"sub": "u-1"}

    async def test_a_rotated_unnamed_key_is_picked_up_early(self, httpx_mock: HTTPXMock) -> None:
        """An issuer that names no keys can rotate its key, and a signature failure triggers the early refetch."""
        clock = FakeClock()
        before = published(RSA_KEY)
        after = published(OTHER_RSA_KEY)
        del before["keys"][0]["kid"], after["keys"][0]["kid"]
        httpx_mock.add_response(url=JWKS_URL, json=before)
        httpx_mock.add_response(url=JWKS_URL, json=after)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY, kid="a"))
        clock.now += 120

        verified = await keys.verify(signed(OTHER_RSA_KEY, kid="b"))

        assert verified.claims == {"sub": "u-1"}

    async def test_a_rotated_key_is_picked_up_for_a_token_without_a_kid(self, httpx_mock: HTTPXMock) -> None:
        """A token that names no key still triggers the early refetch when the cached key does not verify it."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, json=published(OTHER_RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY, kid=None))
        clock.now += 120

        verified = await keys.verify(signed(OTHER_RSA_KEY, kid=None))

        assert verified.claims == {"sub": "u-1"}

    async def test_an_issuer_that_names_no_keys_is_not_refetched_for_each_kid(self, httpx_mock: HTTPXMock) -> None:
        """A token's ``kid`` cannot match an issuer that names no keys, so it does not trigger refetches."""
        clock = FakeClock()
        unnamed = published(RSA_KEY)
        del unnamed["keys"][0]["kid"]
        httpx_mock.add_response(url=JWKS_URL, json=unnamed)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)

        for _ in range(5):
            await keys.verify(signed(RSA_KEY))
            clock.now += 61

        assert len(httpx_mock.get_requests()) == 1

    async def test_a_key_published_for_another_algorithm_is_not_used(self, httpx_mock: HTTPXMock) -> None:
        """A key whose ``alg`` names another algorithm never verifies this one."""
        document = published(RSA_KEY)
        document["keys"][0]["alg"] = "PS256"
        httpx_mock.add_response(url=JWKS_URL, json=document, is_reusable=True)

        with pytest.raises(IdentityFetchError, match="key the issuer does not publish"):
            await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

    async def test_accepts_a_private_header_parameter(self, httpx_mock: HTTPXMock) -> None:
        """Some providers add their own header parameters, which do not affect the signature check."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY, **{"pi.atm": "x"}))

        assert verified.header["pi.atm"] == "x"

    async def test_refuses_a_correctly_signed_token_with_a_critical_header_parameter(self) -> None:
        """RFC 7515 section 4.1.11 requires refusing a ``crit`` parameter the reader does not understand."""
        header = _b64(json.dumps({"alg": "RS256", "kid": "rsa-1", "crit": ["zzz"], "zzz": 1}).encode())
        payload = _b64(b'{"sub": "u-1"}')
        signature = _b64(JWSRegistry.algorithms["RS256"].sign(f"{header}.{payload}".encode(), RSA_KEY))

        with pytest.raises(IdentityFetchError, match="critical header parameter"):
            await IssuerSigningKeys(JWKS_URL).verify(f"{header}.{payload}.{signature}")

    @pytest.mark.parametrize("header", [["alg"], "alg"])
    async def test_refuses_a_header_that_is_not_a_json_object(self, header: object) -> None:
        """A header segment that decodes to another JSON value is not a signed token."""
        token = f"{_b64(json.dumps(header).encode())}.{_b64(b'{}')}.sig"

        with pytest.raises(IdentityFetchError, match="not a signed token"):
            await IssuerSigningKeys(JWKS_URL).verify(token)

    async def test_accepts_a_large_protected_header(self, httpx_mock: HTTPXMock) -> None:
        """A certificate chain in the header makes it large, and a size limit for smaller headers must not refuse it."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY, x5c=[_b64(bytes(1500))]))

        assert verified.claims == {"sub": "u-1"}

    async def test_refuses_a_deeply_nested_header(self) -> None:
        """A header that nests too deeply to decode is not a signed token."""
        token = f"{_b64(b'[' * 12000)}.{_b64(b'{}')}.sig"

        with pytest.raises(IdentityFetchError, match="not a signed token"):
            await IssuerSigningKeys(JWKS_URL).verify(token)

    async def test_refuses_a_deeply_nested_payload(self, httpx_mock: HTTPXMock) -> None:
        """A signed payload that nests too deeply to decode is not a claims object."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        payload = b"[" * 30000 + b"]" * 30000
        token = jws.serialize_compact({"alg": "RS256", "kid": "rsa-1"}, payload, RSA_KEY)

        with pytest.raises(IdentityFetchError, match="claims are not a JSON object"):
            await IssuerSigningKeys(JWKS_URL).verify(token)

    async def test_refuses_a_token_that_cannot_be_encoded(self) -> None:
        """A token holding a lone surrogate is refused, not raised as an encoding error."""
        with pytest.raises(IdentityFetchError, match="not a signed token"):
            await IssuerSigningKeys(JWKS_URL).verify("\ud800.a.b")

    async def test_accepts_an_elliptic_curve_key(self, httpx_mock: HTTPXMock) -> None:
        """Every public-key family on the list verifies, not only RSA."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY, EC_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(EC_KEY, alg="ES256"))

        assert verified.claims == {"sub": "u-1"}

    async def test_refuses_a_token_signed_by_another_key_with_a_published_kid(self, httpx_mock: HTTPXMock) -> None:
        """A forged token that borrows a real key ID fails the signature check."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        forged = signed(OTHER_RSA_KEY, kid="rsa-1")

        with pytest.raises(IdentityFetchError, match="signature did not verify"):
            await IssuerSigningKeys(JWKS_URL).verify(forged)

    @pytest.mark.parametrize("alg", ["none", "HS256", "Ed25519", ["RS256"], {"alg": "RS256"}, 5])
    async def test_refuses_an_algorithm_outside_the_public_key_list(self, alg: object) -> None:
        """``none`` and shared-secret MACs are refused before any key is fetched."""
        token = f"{_b64(json.dumps({'alg': alg, 'kid': 'rsa-1'}).encode())}.{_b64(b'{}')}.sig"

        with pytest.raises(IdentityFetchError, match="signing algorithm that is not accepted"):
            await IssuerSigningKeys(JWKS_URL).verify(token)

    @pytest.mark.parametrize("token", ["", "not-a-token", "a.b", "a.b.c"])
    async def test_refuses_a_token_that_is_not_a_signed_token(self, token: str) -> None:
        """Anything that does not parse as a compact signed token is refused."""
        with pytest.raises(IdentityFetchError, match="not a signed token"):
            await IssuerSigningKeys(JWKS_URL).verify(token)

    async def test_ignores_a_key_carried_in_the_token_header(self, httpx_mock: HTTPXMock) -> None:
        """Only published keys verify, so a token cannot vouch for itself with ``jwk`` or ``jku``."""
        httpx_mock.add_response(url=JWKS_URL, json=published(EC_KEY))
        attacker_key = jwk.ECKey.generate_key("P-256")
        forged = signed(
            attacker_key,
            alg="ES256",
            kid="ec-1",
            jwk=attacker_key.as_dict(private=False),
            jku="https://attacker.example/keys",
        )

        with pytest.raises(IdentityFetchError, match="signature did not verify"):
            await IssuerSigningKeys(JWKS_URL).verify(forged)

        assert [str(request.url) for request in httpx_mock.get_requests()] == [JWKS_URL]

    async def test_a_malformed_header_parameter_is_reported_without_a_refetch(self, httpx_mock: HTTPXMock) -> None:
        """A header the registry refuses is the token's fault, so no key set fetch can help."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 120
        header = _b64(json.dumps({"alg": "RS256", "kid": 5}).encode())
        payload = _b64(b'{"sub": "u-1"}')
        signature = _b64(JWSRegistry.algorithms["RS256"].sign(f"{header}.{payload}".encode(), RSA_KEY))

        with pytest.raises(IdentityFetchError, match="header is not valid") as excinfo:
            await keys.verify(f"{header}.{payload}.{signature}")

        assert excinfo.value.__cause__ is not None
        assert len(httpx_mock.get_requests()) == 1

    async def test_a_forged_token_after_a_minute_refetches_once_and_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """A forged token naming a published key spends at most one refetch a minute, and is still refused."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY), is_reusable=True)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 120

        for _ in range(2):
            with pytest.raises(IdentityFetchError, match="signature did not verify"):
                await keys.verify(signed(OTHER_RSA_KEY, kid="rsa-1"))
            clock.now += 10

        assert len(httpx_mock.get_requests()) == 2

    async def test_a_key_replaced_under_the_same_kid_is_picked_up_early(self, httpx_mock: HTTPXMock) -> None:
        """An issuer that reuses a ``kid`` for new key material recovers within a minute, not an hour."""
        clock = FakeClock()
        replaced = published(OTHER_RSA_KEY)
        replaced["keys"][0]["kid"] = "rsa-1"
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, json=replaced)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 120

        verified = await keys.verify(signed(OTHER_RSA_KEY, kid="rsa-1"))

        assert verified.claims == {"sub": "u-1"}

    async def test_refuses_a_payload_that_is_not_a_json_object(self, httpx_mock: HTTPXMock) -> None:
        """A verified token must still carry a claims object."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        token = jws.serialize_compact({"alg": "RS256", "kid": "rsa-1"}, b"[1, 2]", RSA_KEY)

        with pytest.raises(IdentityFetchError, match="claims"):
            await IssuerSigningKeys(JWKS_URL).verify(token)


class TestKeySelection:
    """Test which published key a token is checked against."""

    async def test_a_token_without_a_kid_uses_the_only_fitting_key(self, httpx_mock: HTTPXMock) -> None:
        """With one key of the token's type, no key ID is needed."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY, EC_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY, kid=None))

        assert verified.claims == {"sub": "u-1"}

    async def test_a_token_without_a_kid_is_tried_against_each_fitting_key(self, httpx_mock: HTTPXMock) -> None:
        """With two keys of the token's type, the one whose signature checks out is used."""
        httpx_mock.add_response(url=JWKS_URL, json=published(OTHER_RSA_KEY, RSA_KEY))

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY, kid=None))

        assert verified.claims == {"sub": "u-1"}

    async def test_a_named_key_of_another_type_does_not_hide_an_unnamed_key(self, httpx_mock: HTTPXMock) -> None:
        """A named EC key does not stop an RS256 token from using the issuer's unnamed RSA key."""
        document = published(RSA_KEY, EC_KEY)
        del document["keys"][0]["kid"]
        httpx_mock.add_response(url=JWKS_URL, json=document)

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY, kid="rsa-a"))

        assert verified.claims == {"sub": "u-1"}

    @pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
    async def test_skips_unusable_keys_in_the_set(self, httpx_mock: HTTPXMock) -> None:
        """A symmetric key, an unknown key type or an encryption key does not spoil the rest of the set."""
        document = published(RSA_KEY)
        document["keys"] += [
            {"kty": "oct", "k": "c2VjcmV0", "kid": "oct-1"},
            {"kty": "weird", "kid": "w-1"},
            {"kty": "EC", "crv": "BP-256", "x": "AA", "y": "AA", "kid": "bp-1"},
            {"kty": "OKP", "crv": "Ed9999", "x": "AA", "kid": "okp-x"},
        ]
        httpx_mock.add_response(url=JWKS_URL, json=document)

        verified = await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

        assert verified.claims == {"sub": "u-1"}

    @pytest.mark.parametrize(
        ("member", "value"),
        [("key_ops", ["encrypt"]), ("key_ops", "verify"), ("key_ops", [1]), ("use", "enc"), ("use", "other")],
    )
    async def test_refuses_a_key_not_published_for_verifying(
        self, httpx_mock: HTTPXMock, member: str, value: object
    ) -> None:
        """Only a key whose ``use`` and ``key_ops`` allow verification, or say nothing, verifies a signature."""
        document = published(RSA_KEY)
        document["keys"][0][member] = value
        httpx_mock.add_response(url=JWKS_URL, json=document, is_reusable=True)

        with pytest.raises(IdentityFetchError, match="key the issuer does not publish"):
            await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

    @pytest.mark.parametrize("entries", [[{"kty": "weird", "kid": "w-1"}], []])
    async def test_warns_when_no_published_key_can_verify(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture, entries: list[Any]
    ) -> None:
        """A key set with no usable key is a provider fault worth reporting."""
        httpx_mock.add_response(url=JWKS_URL, json={"keys": entries}, is_reusable=True)

        with caplog.at_level(logging.WARNING, logger="apron_auth.providers._jwks"), pytest.raises(IdentityFetchError):
            await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

        assert "no key that can verify a signature" in caplog.text


class TestCaching:
    """Test when the key set is fetched again."""

    async def test_reuses_the_keys_within_an_hour(self, httpx_mock: HTTPXMock) -> None:
        """Two sign-ins inside the cache window cause one fetch."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)

        await keys.verify(signed(RSA_KEY))
        clock.now += 3599
        await keys.verify(signed(RSA_KEY))

        assert len(httpx_mock.get_requests()) == 1

    async def test_refetches_after_an_hour(self, httpx_mock: HTTPXMock) -> None:
        """A removed key stops verifying once the cache expires."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, json=published(OTHER_RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 3600

        with pytest.raises(IdentityFetchError, match="key the issuer does not publish"):
            await keys.verify(signed(RSA_KEY))

    async def test_an_unknown_kid_triggers_one_refetch(self, httpx_mock: HTTPXMock) -> None:
        """A rotated-in key is picked up without waiting for the hour."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY, OTHER_RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 61

        verified = await keys.verify(signed(OTHER_RSA_KEY))

        assert verified.claims == {"sub": "u-1"}

    async def test_concurrent_sign_ins_with_a_rotated_key_all_verify(self) -> None:
        """A sign-in that waited on another's refetch checks again against the keys it stored."""
        clock = FakeClock()
        documents = [published(RSA_KEY), published(RSA_KEY, OTHER_RSA_KEY)]
        fetches: list[str] = []

        async def respond(request: httpx.Request) -> httpx.Response:
            fetches.append(str(request.url))
            await asyncio.sleep(0)
            return httpx.Response(200, json=documents[min(len(fetches), len(documents)) - 1])

        keys = IssuerSigningKeys(JWKS_URL, transport_factory=lambda url: httpx.MockTransport(respond), clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 61

        results = await asyncio.gather(*(keys.verify(signed(OTHER_RSA_KEY)) for _ in range(3)))

        assert len(results) == 3
        assert len(fetches) == 2

    async def test_a_failed_early_refetch_keeps_the_valid_keys(
        self, httpx_mock: HTTPXMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A key set still within its hour keeps verifying, and the unknown key is reported as unpublished."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, status_code=503)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 61

        with (
            caplog.at_level(logging.WARNING, logger="apron_auth.providers._jwks"),
            pytest.raises(IdentityFetchError, match="key the issuer does not publish"),
        ):
            await keys.verify(signed(OTHER_RSA_KEY))
        verified = await keys.verify(signed(RSA_KEY))

        assert verified.claims == {"sub": "u-1"}
        assert "HTTP 503" in caplog.text

    async def test_a_failed_early_refetch_does_not_block_the_hourly_refetch(self, httpx_mock: HTTPXMock) -> None:
        """Once the issuer recovers, the hourly refetch runs even if an early refetch failed just before it."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, status_code=503)
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now = 1000 + 3590
        with pytest.raises(IdentityFetchError, match="key the issuer does not publish"):
            await keys.verify(signed(OTHER_RSA_KEY))
        clock.now = 1000 + 3601

        verified = await keys.verify(signed(RSA_KEY))

        assert verified.claims == {"sub": "u-1"}
        assert len(httpx_mock.get_requests()) == 3

    async def test_a_failed_refetch_also_counts_toward_the_rate_limit(self, httpx_mock: HTTPXMock) -> None:
        """While the key set endpoint fails, unknown key IDs still refetch at most once a minute."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        httpx_mock.add_response(url=JWKS_URL, status_code=503, is_reusable=True)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))
        clock.now += 61

        for _ in range(5):
            clock.now += 10
            with pytest.raises(IdentityFetchError):
                await keys.verify(signed(OTHER_RSA_KEY))

        assert len(httpx_mock.get_requests()) == 2

    async def test_unknown_kids_refetch_at_most_once_a_minute(self, httpx_mock: HTTPXMock) -> None:
        """A stream of tokens naming unknown keys cannot flood the issuer."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY), is_reusable=True)
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)
        await keys.verify(signed(RSA_KEY))

        for _ in range(5):
            clock.now += 10
            with pytest.raises(IdentityFetchError, match="key the issuer does not publish"):
                await keys.verify(signed(OTHER_RSA_KEY))

        assert len(httpx_mock.get_requests()) == 1

    async def test_concurrent_first_sign_ins_share_one_fetch(self, httpx_mock: HTTPXMock) -> None:
        """Sign-ins that arrive before the first fetch finishes wait for it."""
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL)

        results = await asyncio.gather(*(keys.verify(signed(RSA_KEY)) for _ in range(5)))

        assert len(results) == 5
        assert len(httpx_mock.get_requests()) == 1


class TestFetchFailures:
    """Test how a failed key-set fetch is reported."""

    async def test_reports_an_unreachable_key_set(self, httpx_mock: HTTPXMock) -> None:
        """A network failure names the condition, not the client library."""
        httpx_mock.add_exception(httpx.ConnectError("boom"), url=JWKS_URL)

        with pytest.raises(IdentityFetchError, match="Failed to fetch the issuer's signing keys: network error"):
            await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

    async def test_a_failed_fetch_is_retried_after_a_minute(self, httpx_mock: HTTPXMock) -> None:
        """An outage is reported without refetching for a minute, and does not stick after that."""
        clock = FakeClock()
        httpx_mock.add_response(url=JWKS_URL, status_code=503)
        httpx_mock.add_response(url=JWKS_URL, json=published(RSA_KEY))
        keys = IssuerSigningKeys(JWKS_URL, clock=clock)

        with pytest.raises(IdentityFetchError, match="HTTP 503"):
            await keys.verify(signed(RSA_KEY))
        clock.now += 30
        with pytest.raises(IdentityFetchError, match="HTTP 503"):
            await keys.verify(signed(RSA_KEY))
        clock.now += 30
        verified = await keys.verify(signed(RSA_KEY))

        assert verified.claims == {"sub": "u-1"}

    @pytest.mark.parametrize("body", [b"not json", b"[]", b'{"keys": "nope"}'])
    async def test_reports_a_document_that_is_not_a_key_set(self, httpx_mock: HTTPXMock, body: bytes) -> None:
        """A response that is not a key set is refused."""
        httpx_mock.add_response(url=JWKS_URL, content=body)

        with pytest.raises(IdentityFetchError, match="signing keys could not be read"):
            await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

    async def test_reports_a_deeply_nested_key_set(self, httpx_mock: HTTPXMock) -> None:
        """A key set that nests too deeply to decode is reported as unreadable, and the failure is rate limited."""
        httpx_mock.add_response(url=JWKS_URL, content=b'{"keys": ' + b"[" * 50000)
        keys = IssuerSigningKeys(JWKS_URL)

        with pytest.raises(IdentityFetchError, match="signing keys could not be read"):
            await keys.verify(signed(RSA_KEY))
        with pytest.raises(IdentityFetchError, match="signing keys could not be read"):
            await keys.verify(signed(RSA_KEY))

        assert len(httpx_mock.get_requests()) == 1

    async def test_does_not_follow_a_redirect(self, httpx_mock: HTTPXMock) -> None:
        """A redirect cannot move the fetch to a host nobody checked, and the error says how to fix it."""
        httpx_mock.add_response(url=JWKS_URL, status_code=302, headers={"Location": "https://attacker.example/keys"})

        with pytest.raises(IdentityFetchError, match="HTTP 302; redirects are not followed"):
            await IssuerSigningKeys(JWKS_URL).verify(signed(RSA_KEY))

        assert [str(request.url) for request in httpx_mock.get_requests()] == [JWKS_URL]

    async def test_reports_a_key_set_url_the_client_cannot_use(self) -> None:
        """A URL that passes the URL rule but not the HTTP client is reported in domain terms."""
        with pytest.raises(IdentityFetchError, match="invalid key set URL"):
            await IssuerSigningKeys("https://sso.example.com/\x00").verify(signed(RSA_KEY))

    async def test_reports_a_transport_that_fails_unexpectedly(self) -> None:
        """A caller transport that raises its own error is a failed fetch, rate limited like any other."""
        calls: list[str] = []

        def fail(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            raise RuntimeError("transport bug")

        keys = IssuerSigningKeys(JWKS_URL, transport_factory=lambda url: httpx.MockTransport(fail))

        for _ in range(2):
            with pytest.raises(IdentityFetchError, match="Failed to fetch the issuer's signing keys"):
                await keys.verify(signed(RSA_KEY))

        assert calls == [JWKS_URL]

    async def test_reports_a_transport_factory_that_refuses_the_connection(self) -> None:
        """Caller code that raises is reported as a refused connection."""

        def refuse(url: str) -> httpx.AsyncBaseTransport:
            raise PermissionError(url)

        with pytest.raises(IdentityFetchError, match="outbound connection refused"):
            await IssuerSigningKeys(JWKS_URL, transport_factory=refuse).verify(signed(RSA_KEY))


class TestEventLoops:
    """Test that one instance serves sign-ins on more than one event loop."""

    def test_contended_use_on_two_event_loops(self) -> None:
        """A handler built once, then used by concurrent sign-ins on two loops, verifies on both."""
        clock = FakeClock()
        fetches: list[str] = []

        async def respond(request: httpx.Request) -> httpx.Response:
            fetches.append(str(request.url))
            await asyncio.sleep(0)
            return httpx.Response(200, json=published(RSA_KEY))

        keys = IssuerSigningKeys(JWKS_URL, transport_factory=lambda url: httpx.MockTransport(respond), clock=clock)

        async def sign_ins() -> int:
            return len(await asyncio.gather(*(keys.verify(signed(RSA_KEY)) for _ in range(3))))

        assert asyncio.run(sign_ins()) == 3
        clock.now += 3600
        assert asyncio.run(sign_ins()) == 3
        assert fetches == [JWKS_URL, JWKS_URL]

    def test_keeps_no_finished_event_loop_alive(self) -> None:
        """Contended use on many loops in turn does not hold each finished loop in memory."""
        clock = FakeClock()

        async def respond(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0)
            return httpx.Response(200, json=published(RSA_KEY))

        keys = IssuerSigningKeys(JWKS_URL, transport_factory=lambda url: httpx.MockTransport(respond), clock=clock)
        finished: list[weakref.ref[asyncio.AbstractEventLoop]] = []

        async def sign_ins() -> None:
            finished.append(weakref.ref(asyncio.get_running_loop()))
            await asyncio.gather(*(keys.verify(signed(RSA_KEY)) for _ in range(3)))

        for _ in range(3):
            clock.now += 3600
            asyncio.run(sign_ins())
        gc.collect()

        assert sum(loop() is not None for loop in finished) <= 1
