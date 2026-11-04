from __future__ import annotations

import httpx
import pytest

from apron_auth._http_errors import HttpFailure, http_failure, response_failure, status_failure
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


class TestResponseFailure:
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
    def test_a_statement_of_when_to_come_back_makes_a_rejection_retryable(self, status: int) -> None:
        """A status alone cannot tell a throttle from a refusal where a server answers both with one."""
        response = httpx.Response(status, headers={"Retry-After": "60"}, request=_REQUEST)

        failure = response_failure(response)

        assert failure == HttpFailure(FailureKind.SERVER_ERROR, f"HTTP {status}")
        assert failure.kind.retryable is True

    @pytest.mark.parametrize("status", [301, 302, 307, 308])
    def test_a_redirect_stays_refused_however_it_states_when_to_come_back(self, status: int) -> None:
        """No wait makes an endpoint stop redirecting, and this library follows no redirect."""
        response = httpx.Response(status, headers={"Retry-After": "60"}, request=_REQUEST)

        failure = response_failure(response)

        assert failure == HttpFailure(FailureKind.REFUSED, f"HTTP {status}")
        assert failure.kind.retryable is False

    @pytest.mark.parametrize("value", ["", " ", "\t"])
    def test_a_header_stating_nothing_states_no_condition(self, value: str) -> None:
        """An empty header is a defect in the response, not the server asking to be called again."""
        response = httpx.Response(403, headers={"Retry-After": value}, request=_REQUEST)

        assert response_failure(response) == HttpFailure(FailureKind.REJECTED, "HTTP 403")

    @pytest.mark.parametrize("status", [429, 500, 503])
    def test_a_status_that_already_states_a_temporary_condition_is_unchanged(self, status: int) -> None:
        response = httpx.Response(status, request=_REQUEST)

        assert response_failure(response) == HttpFailure(FailureKind.SERVER_ERROR, f"HTTP {status}")

    def test_a_raised_status_error_is_read_the_same_way(self) -> None:
        """The two entry points answer alike, so a path that catches a status error gains the same rule."""
        response = httpx.Response(403, headers={"Retry-After": "60"}, request=_REQUEST)
        exc = httpx.HTTPStatusError("Forbidden", request=_REQUEST, response=response)

        assert http_failure(exc) == response_failure(response)
        assert http_failure(exc).kind is FailureKind.SERVER_ERROR


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
