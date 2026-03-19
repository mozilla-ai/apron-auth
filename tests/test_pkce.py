from __future__ import annotations

import base64
import hashlib

from any_auth.pkce import generate_code_challenge, generate_code_verifier


def test_verifier_length():
    verifier = generate_code_verifier()
    assert 43 <= len(verifier) <= 128


def test_verifier_url_safe():
    verifier = generate_code_verifier()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert all(c in allowed for c in verifier)


def test_verifier_uniqueness():
    verifiers = {generate_code_verifier() for _ in range(100)}
    assert len(verifiers) == 100


def test_challenge_is_s256():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = generate_code_challenge(verifier)
    expected_digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    expected = base64.urlsafe_b64encode(expected_digest).decode("utf-8").rstrip("=")
    assert challenge == expected


def test_challenge_no_padding():
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    assert "=" not in challenge


def test_challenge_deterministic():
    verifier = generate_code_verifier()
    assert generate_code_challenge(verifier) == generate_code_challenge(verifier)
