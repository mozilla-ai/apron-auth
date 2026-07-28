from __future__ import annotations

from apron_auth.errors import (
    ConfigurationError,
    OAuthError,
    PermanentOAuthError,
    RevocationError,
    StateError,
    TokenExchangeError,
    TokenRefreshError,
)


def test_all_errors_inherit_from_oauth_error():
    for cls in (
        TokenExchangeError,
        TokenRefreshError,
        PermanentOAuthError,
        RevocationError,
        StateError,
        ConfigurationError,
    ):
        assert issubclass(cls, OAuthError)
        assert issubclass(cls, Exception)


def test_errors_are_distinct():
    classes = [
        OAuthError,
        TokenExchangeError,
        TokenRefreshError,
        PermanentOAuthError,
        RevocationError,
        StateError,
        ConfigurationError,
    ]
    assert len(classes) == len(set(classes))


def test_error_message_preserved():
    err = TokenExchangeError("token endpoint returned 400")
    assert str(err) == "token endpoint returned 400"


def test_error_chaining():
    cause = ValueError("bad response")
    err = TokenExchangeError("exchange failed")
    err.__cause__ = cause
    assert err.__cause__ is cause


def test_error_code_defaults_to_empty() -> None:
    assert OAuthError("boom").error_code == ""
    assert ConfigurationError("misconfigured").error_code == ""


def test_error_code_stored_and_message_preserved() -> None:
    err = PermanentOAuthError("invalid_grant: token revoked", error_code="invalid_grant")
    assert err.error_code == "invalid_grant"
    assert str(err) == "invalid_grant: token revoked"


def test_well_known_error_code_constants() -> None:
    from apron_auth import (
        INVALID_CLIENT,
        INVALID_GRANT,
        SERVER_ERROR,
        TEMPORARILY_UNAVAILABLE,
        UNAUTHORIZED_CLIENT,
    )

    assert INVALID_GRANT == "invalid_grant"
    assert INVALID_CLIENT == "invalid_client"
    assert UNAUTHORIZED_CLIENT == "unauthorized_client"
    assert SERVER_ERROR == "server_error"
    assert TEMPORARILY_UNAVAILABLE == "temporarily_unavailable"
