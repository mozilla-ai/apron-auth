from __future__ import annotations

import base64
import json

import pytest
from joserfc import jwk, jws

from apron_auth._jwt import jws_registry, unverified_claims

RSA_KEY = jwk.RSAKey.generate_key(2048, parameters={"kid": "rsa-1"})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def compact(*segments: bytes) -> str:
    """Return the segments joined as a compact token, with no signature check possible."""
    return ".".join(_b64(segment) for segment in segments)


# RFC 7797 lets a header mark the payload as sent without base64url encoding.
UNENCODED_PAYLOAD_TOKEN = ".".join(
    [_b64(b'{"alg":"RS256","b64":false,"crit":["b64"]}'), '{"nonce":"n-1"}', _b64(b"sig")]
)


def signed(claims: dict[str, object], **header: object) -> str:
    """Return a compact token signed with the test key."""
    return jws.serialize_compact(
        {"alg": "RS256", "kid": RSA_KEY.kid, **header},
        json.dumps(claims).encode(),
        RSA_KEY,
        registry=jws_registry(["RS256"]),
    )


class TestUnverifiedClaims:
    """Test that a token's claims are read without the issuer's key set."""

    def test_returns_the_claims_of_a_signed_token(self) -> None:
        assert unverified_claims(signed({"sub": "u-1", "nonce": "n-1"})) == {"sub": "u-1", "nonce": "n-1"}

    def test_reads_a_token_whose_header_holds_a_certificate_chain(self) -> None:
        assert unverified_claims(signed({"sub": "u-1"}, x5c=["A" * 4000])) == {"sub": "u-1"}

    @pytest.mark.parametrize(
        "token",
        [
            "not-a-token",
            "",
            compact(b'{"alg":"RS256"}', b"[1]", b"sig"),
            compact(b'{"alg":"RS256"}', b"not json", b"sig"),
            compact(b'{"alg":"RS256"}', b"{}", b"sig", b"x", b"y"),
            compact(b'["alg","b64"]', b"{}", b"sig"),
            compact(b'"b64alg"', b"{}", b"sig"),
            UNENCODED_PAYLOAD_TOKEN,
            "\ud800.\ud800.\ud800",
            compact(b'{"alg":"RS256"}', b'{"exp":NaN}', b"sig"),
            compact(b'{"alg":"RS256"}', b'{"exp":Infinity}', b"sig"),
            compact(b'{"alg":"RS256"}', b'{"exp":-Infinity}', b"sig"),
            compact(b'{"alg":"RS256"}', b'{"exp":1e400}', b"sig"),
            compact(b'{"alg":"RS256"}', b'{"iat":-1e400}', b"sig"),
        ],
        ids=[
            "not-compact",
            "empty",
            "claims-not-object",
            "claims-not-json",
            "encrypted-shape",
            "header-list",
            "header-string",
            "unencoded-payload",
            "unencodable",
            "claims-naming-nan",
            "claims-naming-infinity",
            "claims-naming-negative-infinity",
            "claims-overflowing-a-float",
            "claims-underflowing-a-float",
        ],
    )
    def test_refuses_a_token_it_cannot_read(self, token: str) -> None:
        with pytest.raises(ValueError, match="not a compact signed token|not a JSON object"):
            unverified_claims(token)

    def test_a_claim_at_the_edge_of_a_float_is_still_read(self) -> None:
        """Only a value a float cannot hold is refused, so the largest one it can is read as it stands."""
        claims = unverified_claims(compact(b'{"alg":"RS256"}', b'{"exp":1.7976931348623157e308}', b"sig"))

        assert claims["exp"] == 1.7976931348623157e308
