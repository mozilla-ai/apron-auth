from __future__ import annotations

import httpx
import pytest

from apron_auth.providers._http_errors import describe_http_error

_REQUEST = httpx.Request("GET", "https://api.example.com/me?token=secret-token")


class TestDescribeHttpError:
    def test_status_error_reports_status_code(self):
        response = httpx.Response(503, request=_REQUEST)
        exc = httpx.HTTPStatusError("Server error", request=_REQUEST, response=response)

        assert describe_http_error(exc) == "HTTP 503"

    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (httpx.ConnectTimeout("connect timed out", request=_REQUEST), "request timed out"),
            (httpx.ReadTimeout("read timed out", request=_REQUEST), "request timed out"),
            (httpx.ConnectError("connection refused", request=_REQUEST), "network error"),
            (httpx.ReadError("connection reset", request=_REQUEST), "network error"),
            (httpx.RemoteProtocolError("bad frame", request=_REQUEST), "request failed"),
            (httpx.TooManyRedirects("redirect loop", request=_REQUEST), "request failed"),
        ],
    )
    def test_transport_error_reports_failure_kind(self, exc: httpx.RequestError, expected: str):
        assert describe_http_error(exc) == expected

    def test_description_omits_url_and_client_text(self):
        exc = httpx.ConnectError(f"Connection refused for url {_REQUEST.url}", request=_REQUEST)

        description = describe_http_error(exc)

        assert "https://" not in description
        assert "secret-token" not in description
        assert type(exc).__name__ not in description
