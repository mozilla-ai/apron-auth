"""The caller's transport factory decides the outbound connection of an identity request."""

from __future__ import annotations

import httpx
import pytest

from apron_auth.errors import FailureKind, IdentityFetchError
from apron_auth.providers._identity_requests import identity_transport


def test_no_factory_states_no_transport() -> None:
    assert identity_transport(None, "https://api.example.com/me", "Example identity") is None


def test_the_factory_chooses_the_transport_for_the_url() -> None:
    chosen = httpx.MockTransport(lambda request: httpx.Response(200))
    asked: list[str] = []

    def factory(url: str) -> httpx.AsyncBaseTransport:
        asked.append(url)
        return chosen

    assert identity_transport(factory, "https://api.example.com/me", "Example identity") is chosen
    assert asked == ["https://api.example.com/me"]


@pytest.mark.parametrize(
    "raised",
    [
        pytest.param(RuntimeError("refused by policy"), id="an error of the caller's own"),
        pytest.param(ValueError("not a validated address"), id="a value error"),
        pytest.param(KeyboardInterrupt(), id="an error outside Exception's own tree"),
    ],
)
def test_a_factory_that_refuses_is_reported_as_a_fault_no_retry_clears(raised: BaseException) -> None:
    """The fault is the caller's policy rather than the provider's, so the same request fails the same way."""

    def factory(url: str) -> httpx.AsyncBaseTransport:
        raise raised

    if isinstance(raised, Exception):
        with pytest.raises(IdentityFetchError) as refusal:
            identity_transport(factory, "https://api.example.com/me", "Example identity")
        assert refusal.value.kind is FailureKind.UNEXPECTED
        assert refusal.value.retryable is False
        assert "Example identity" in str(refusal.value)
    else:
        with pytest.raises(type(raised)):
            identity_transport(factory, "https://api.example.com/me", "Example identity")
