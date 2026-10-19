from __future__ import annotations

import httpx
import pytest

from apron_auth._http_errors import HttpFailure, http_failure, status_failure
from apron_auth.errors import FailureKind

_REQUEST = httpx.Request("GET", "https://api.example.com/me?token=secret-token")


class TestHttpFailure:
    def test_status_error_reports_status_code(self) -> None:
        response = httpx.Response(503, request=_REQUEST)
        exc = httpx.HTTPStatusError("Server error", request=_REQUEST, response=response)

        assert http_failure(exc) == HttpFailure(FailureKind.SERVER_ERROR, "HTTP 503")

    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (httpx.ConnectTimeout("connect timed out", request=_REQUEST), (FailureKind.TIMEOUT, "request timed out")),
            (httpx.ReadTimeout("read timed out", request=_REQUEST), (FailureKind.TIMEOUT, "request timed out")),
            (httpx.ConnectError("connection refused", request=_REQUEST), (FailureKind.UNREACHABLE, "network error")),
            (httpx.ReadError("connection reset", request=_REQUEST), (FailureKind.UNREACHABLE, "network error")),
            (httpx.RemoteProtocolError("bad frame", request=_REQUEST), (FailureKind.UNREACHABLE, "request failed")),
            (httpx.TooManyRedirects("redirect loop", request=_REQUEST), (FailureKind.UNREACHABLE, "request failed")),
        ],
    )
    def test_transport_error_reports_its_kind(self, exc: httpx.RequestError, expected: tuple[FailureKind, str]) -> None:
        assert http_failure(exc) == HttpFailure(*expected)

    def test_description_omits_url_and_client_text(self) -> None:
        exc = httpx.ConnectError(f"Connection refused for url {_REQUEST.url}", request=_REQUEST)

        description = http_failure(exc).description

        assert "https://" not in description
        assert "secret-token" not in description
        assert type(exc).__name__ not in description


class TestStatusFailure:
    @pytest.mark.parametrize("status", [500, 502, 503, 504, 429])
    def test_server_errors_and_rate_limits_may_pass_on_retry(self, status: int) -> None:
        failure = status_failure(status)

        assert failure == HttpFailure(FailureKind.SERVER_ERROR, f"HTTP {status}")
        assert failure.kind.retryable is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
    def test_client_errors_are_rejections(self, status: int) -> None:
        assert status_failure(status) == HttpFailure(FailureKind.REJECTED, f"HTTP {status}")

    @pytest.mark.parametrize("status", [301, 302, 307, 308])
    def test_redirects_are_refused(self, status: int) -> None:
        assert status_failure(status) == HttpFailure(FailureKind.REFUSED, f"HTTP {status}")
