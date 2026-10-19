from __future__ import annotations

import pytest

from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    IdentityNotSupportedError,
    IdentityScopeNotGrantedError,
    IssuerValidationError,
    McpDiscoveryError,
    McpRegistrationError,
    NonceValidationError,
    OAuthError,
    OidcDiscoveryError,
    RevocationError,
    StateError,
    TokenEndpointError,
    TokenExchangeError,
    TokenExpiredError,
    TokenRefreshError,
    TokenValidationError,
    TokenValidationReason,
)

MULTI_KIND_CLASSES = (
    IdentityFetchError,
    McpDiscoveryError,
    McpRegistrationError,
    OidcDiscoveryError,
    RevocationError,
    TokenExchangeError,
    TokenRefreshError,
)

SINGLE_KIND_CLASSES = {
    ConfigurationError: FailureKind.CONFIGURATION,
    IdentityNotSupportedError: FailureKind.CONFIGURATION,
    IdentityScopeNotGrantedError: FailureKind.REJECTED,
    IssuerValidationError: FailureKind.REFUSED,
    NonceValidationError: FailureKind.REFUSED,
    StateError: FailureKind.REFUSED,
}


def test_all_errors_inherit_from_oauth_error() -> None:
    for cls in (*MULTI_KIND_CLASSES, *SINGLE_KIND_CLASSES):
        assert issubclass(cls, OAuthError)
        assert issubclass(cls, Exception)


def test_errors_are_distinct() -> None:
    classes = [OAuthError, *MULTI_KIND_CLASSES, *SINGLE_KIND_CLASSES]
    assert len(classes) == len(set(classes))


def test_error_message_preserved() -> None:
    err = TokenExchangeError("token endpoint returned 400", kind=FailureKind.REJECTED)
    assert str(err) == "token endpoint returned 400"


class TestFailureKind:
    def test_members_are_in_alphabetical_order(self) -> None:
        names = [member.name for member in FailureKind]
        assert names == sorted(names)

    @pytest.mark.parametrize("kind", [FailureKind.SERVER_ERROR, FailureKind.TIMEOUT, FailureKind.UNREACHABLE])
    def test_retryable_kinds(self, kind: FailureKind) -> None:
        assert kind.retryable is True

    @pytest.mark.parametrize(
        "kind", [FailureKind.CONFIGURATION, FailureKind.REFUSED, FailureKind.REJECTED, FailureKind.UNEXPECTED]
    )
    def test_kinds_that_cannot_be_retried(self, kind: FailureKind) -> None:
        assert kind.retryable is False

    def test_values_are_the_lowercase_names(self) -> None:
        assert FailureKind.SERVER_ERROR == "server_error"
        assert FailureKind("timeout") is FailureKind.TIMEOUT


class TestKindOnErrors:
    @pytest.mark.parametrize(("cls", "expected"), list(SINGLE_KIND_CLASSES.items()))
    def test_single_kind_class_defaults_its_kind(self, cls: type[OAuthError], expected: FailureKind) -> None:
        err = cls("boom")
        assert err.kind is expected
        assert err.retryable is expected.retryable

    @pytest.mark.parametrize("cls", MULTI_KIND_CLASSES)
    def test_multi_kind_class_without_a_kind_is_unexpected(self, cls: type[OAuthError]) -> None:
        err = cls("boom")
        assert err.kind is FailureKind.UNEXPECTED
        assert err.retryable is False
        assert str(err) == "boom"

    @pytest.mark.parametrize("cls", MULTI_KIND_CLASSES)
    def test_multi_kind_class_carries_the_given_kind(self, cls: type[OAuthError]) -> None:
        err = cls("boom", kind=FailureKind.TIMEOUT)
        assert err.kind is FailureKind.TIMEOUT
        assert err.retryable is True

    def test_a_given_kind_overrides_the_default(self) -> None:
        err = ConfigurationError("boom", kind=FailureKind.UNEXPECTED)
        assert err.kind is FailureKind.UNEXPECTED

    def test_base_class_without_a_kind_is_unexpected(self) -> None:
        assert OAuthError("boom").kind is FailureKind.UNEXPECTED

    def test_kind_must_be_a_member(self) -> None:
        with pytest.raises(TypeError, match="kind"):
            TokenExchangeError("boom", kind="timeout")  # type: ignore[arg-type]


class TestTokenEndpointErrors:
    def test_error_code_defaults_to_empty(self) -> None:
        assert TokenExchangeError("boom", kind=FailureKind.REJECTED).error_code == ""
        assert TokenRefreshError("boom", kind=FailureKind.REJECTED).error_code == ""

    def test_error_code_stored_and_message_preserved(self) -> None:
        err = TokenRefreshError("invalid_grant: token revoked", kind=FailureKind.REJECTED, error_code="invalid_grant")
        assert err.error_code == "invalid_grant"
        assert str(err) == "invalid_grant: token revoked"
        assert isinstance(err, TokenEndpointError)

    def test_only_the_token_endpoint_family_carries_an_error_code(self) -> None:
        assert not hasattr(ConfigurationError("boom"), "error_code")
        assert not hasattr(RevocationError("boom", kind=FailureKind.REJECTED), "error_code")

    def test_token_endpoint_error_without_a_kind_is_unexpected(self) -> None:
        assert TokenEndpointError("boom").kind is FailureKind.UNEXPECTED


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


def test_identity_scope_not_granted_is_an_identity_fetch_error() -> None:
    err = IdentityScopeNotGrantedError("scope missing")
    assert isinstance(err, IdentityFetchError)
    assert IdentityScopeNotGrantedError is not IdentityFetchError


def test_identity_not_supported_is_a_configuration_error() -> None:
    assert issubclass(IdentityNotSupportedError, ConfigurationError)


def test_permanent_oauth_error_is_gone() -> None:
    import apron_auth
    import apron_auth.errors

    assert not hasattr(apron_auth.errors, "PermanentOAuthError")
    assert "PermanentOAuthError" not in apron_auth.__all__


class TestTokenValidationError:
    def test_reasons_are_in_alphabetical_order(self) -> None:
        names = [member.name for member in TokenValidationReason]
        assert names == sorted(names)

    def test_a_refusal_needs_a_reason(self) -> None:
        with pytest.raises(TypeError, match="reason"):
            TokenValidationError("boom")  # type: ignore[call-arg]

    def test_a_refusal_is_a_refused_identity_fetch(self) -> None:
        err = TokenValidationError("boom", reason=TokenValidationReason.SIGNATURE)
        assert isinstance(err, IdentityFetchError)
        assert err.kind is FailureKind.REFUSED
        assert err.retryable is False
        assert err.reason is TokenValidationReason.SIGNATURE

    def test_expired_carries_its_own_reason(self) -> None:
        err = TokenExpiredError("boom")
        assert isinstance(err, TokenValidationError)
        assert err.reason is TokenValidationReason.EXPIRED

    def test_the_old_name_is_gone(self) -> None:
        import apron_auth.errors

        assert not hasattr(apron_auth.errors, "TokenVerificationError")


class TestClassificationIsReadOnly:
    def test_a_kind_cannot_be_changed_after_construction(self) -> None:
        err = TokenExchangeError("boom", kind=FailureKind.REJECTED)
        with pytest.raises(AttributeError):
            err.kind = FailureKind.TIMEOUT  # type: ignore[misc]

    def test_a_reason_cannot_be_changed_after_construction(self) -> None:
        err = TokenValidationError("boom", reason=TokenValidationReason.SIGNATURE)
        with pytest.raises(AttributeError):
            err.reason = TokenValidationReason.CLAIMS  # type: ignore[misc]

    def test_retryable_cannot_be_changed_on_a_member(self) -> None:
        with pytest.raises(AttributeError):
            FailureKind.TIMEOUT.retryable = False  # type: ignore[misc]
