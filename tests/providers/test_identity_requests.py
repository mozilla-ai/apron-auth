from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.providers._identity_requests import fetch_identity_json

URL = "https://provider.example.com/me"
TOKEN = "access-SECRET-xyz"  # pragma: allowlist secret


async def _error(request_url: str = URL, token: str = TOKEN) -> IdentityFetchError:
    async with httpx.AsyncClient() as client:
        with pytest.raises(IdentityFetchError) as exc_info:
            await fetch_identity_json(
                client.get(request_url, headers={"Authorization": f"Bearer {token}"}),
                "Example identity",
            )
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    return exc_info.value


async def test_returns_the_decoded_body(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=URL, json={"sub": "u-1"})

    async with httpx.AsyncClient() as client:
        payload = await fetch_identity_json(client.get(URL), "Example identity")

    assert payload == {"sub": "u-1"}


async def test_status_error_names_the_status(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=URL, status_code=401)

    error = await _error()

    assert str(error) == "Failed to fetch Example identity: HTTP 401"


async def test_transport_error_names_the_failure_kind(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_exception(httpx.ConnectError(f"raw transport text {URL}"))

    error = await _error()

    assert str(error) == "Failed to fetch Example identity: network error"


async def test_unreadable_body_is_a_parse_failure(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=URL, content=b"not-json")

    error = await _error()

    assert str(error) == "Failed to parse Example identity response"


async def test_invalid_url_is_a_fetch_failure() -> None:
    error = await _error(f"https://provider.example.com/{TOKEN}\x00")

    assert str(error) == "Failed to fetch Example identity: invalid URL"


async def test_token_that_cannot_be_sent_is_a_fetch_failure() -> None:
    token = "access-SECRET-\u00e9"

    error = await _error(token=token)

    assert str(error) == "Failed to fetch Example identity: request failed"
    assert token not in repr(error.args)


async def test_deeply_nested_body_is_a_parse_failure(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=URL, content=b"[" * 100_000 + b"]" * 100_000)

    error = await _error()

    assert str(error) == "Failed to parse Example identity response"
