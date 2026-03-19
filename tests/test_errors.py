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
