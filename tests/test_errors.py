from __future__ import annotations

import pickle

import pytest

from apron_auth import errors
from apron_auth.errors import (
    AuthorizationResponseError,
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
    AuthorizationResponseError,
    IdentityFetchError,
    McpDiscoveryError,
    McpRegistrationError,
    OidcDiscoveryError,
    RevocationError,
    TokenExchangeError,
    TokenRefreshError,
)

# The phases whose request is never presented again, so their kind never makes them retryable.
NEVER_RETRYABLE_CLASSES = (AuthorizationResponseError, TokenExchangeError)

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


# The error families that report a provider's own code, which every other family must not.
CODE_CARRYING_FAMILIES = (
    AuthorizationResponseError,
    IdentityFetchError,
    RevocationError,
    TokenEndpointError,
)


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
        assert err.retryable is (cls not in NEVER_RETRYABLE_CLASSES)

    def test_a_given_kind_overrides_the_default(self) -> None:
        err = ConfigurationError("boom", kind=FailureKind.UNEXPECTED)
        assert err.kind is FailureKind.UNEXPECTED

    def test_base_class_without_a_kind_is_unexpected(self) -> None:
        assert OAuthError("boom").kind is FailureKind.UNEXPECTED

    def test_kind_must_be_a_member(self) -> None:
        with pytest.raises(TypeError, match="kind"):
            TokenExchangeError("boom", kind="timeout")  # type: ignore[arg-type]


class TestAuthorizationResponseError:
    """The authorization endpoint answered with an error, so no code was issued."""

    def test_error_code_defaults_to_empty(self) -> None:
        assert AuthorizationResponseError("boom", kind=FailureKind.REJECTED).error_code == ""

    def test_a_recognized_code_is_kept_and_the_message_is_left_alone(self) -> None:
        err = AuthorizationResponseError(
            "authorization request was refused", kind=FailureKind.REJECTED, error_code="access_denied"
        )

        assert err.error_code == "access_denied"
        assert str(err) == "authorization request was refused"

    @pytest.mark.parametrize(
        "code",
        [
            pytest.param({"not": "a code"}, id="a mapping"),
            pytest.param(["access_denied"], id="a list"),
            pytest.param(7, id="a number"),
            pytest.param("Access Denied", id="not an identifier"),
            pytest.param("a" * 200, id="longer than any code"),
        ],
    )
    def test_a_value_of_another_shape_reads_as_absent(self, code: object) -> None:
        """A server chooses this field's text, so only a value shaped like a code is comparable."""
        err = AuthorizationResponseError("boom", kind=FailureKind.REJECTED, error_code=code)  # ty: ignore[invalid-argument-type]

        assert err.error_code == ""

    def test_it_is_not_a_token_endpoint_failure(self) -> None:
        """No code was redeemed, so a caller handling token-endpoint failures must not catch this."""
        err = AuthorizationResponseError("boom", kind=FailureKind.REJECTED)

        assert isinstance(err, OAuthError)
        assert not isinstance(err, TokenEndpointError)

    def test_the_kind_says_what_went_wrong_without_promising_a_retry(self) -> None:
        """An outage and a refusal read differently, and neither is answered by presenting this response again."""
        refused = AuthorizationResponseError("boom", kind=FailureKind.REJECTED, error_code="access_denied")
        outage = AuthorizationResponseError("boom", kind=FailureKind.SERVER_ERROR, error_code="temporarily_unavailable")

        assert refused.kind is FailureKind.REJECTED
        assert outage.kind is FailureKind.SERVER_ERROR
        assert refused.retryable is False
        assert outage.retryable is False


class TestTokenEndpointErrors:
    def test_error_code_defaults_to_empty(self) -> None:
        assert TokenExchangeError("boom", kind=FailureKind.REJECTED).error_code == ""
        assert TokenRefreshError("boom", kind=FailureKind.REJECTED).error_code == ""

    def test_error_code_stored_and_message_preserved(self) -> None:
        err = TokenRefreshError("invalid_grant: token revoked", kind=FailureKind.REJECTED, error_code="invalid_grant")
        assert err.error_code == "invalid_grant"
        assert str(err) == "invalid_grant: token revoked"
        assert isinstance(err, TokenEndpointError)

    def test_an_error_outside_the_code_carrying_families_has_none(self) -> None:
        """A family reports a code only where a step on its path reads one off a response."""
        assert not hasattr(ConfigurationError("boom"), "error_code")
        assert not hasattr(StateError("boom"), "error_code")

    @pytest.mark.parametrize("family", CODE_CARRYING_FAMILIES, ids=lambda family: family.__name__)
    def test_every_family_reporting_a_code_shapes_it_the_same_way(self, family: type[OAuthError]) -> None:
        """A family deciding the shape itself could report a value the others report as absent."""
        kept = family("boom", kind=FailureKind.REJECTED, error_code="invalid_grant")
        refused = family("boom", kind=FailureKind.REJECTED, error_code="Invalid Grant")

        assert kept.error_code == "invalid_grant"
        assert refused.error_code == ""

    def test_no_other_family_reports_a_code(self) -> None:
        """A family added later reports a code only by joining one of these, which holds it to the rule."""
        reporting = {
            value.__name__
            for value in vars(errors).values()
            if isinstance(value, type)
            and issubclass(value, OAuthError)
            and hasattr(value, "error_code")
            and not value.__name__.startswith("_")
        }
        covered = {
            value.__name__
            for value in vars(errors).values()
            if isinstance(value, type) and issubclass(value, tuple(CODE_CARRYING_FAMILIES))
        }

        assert reporting == covered

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(TokenValidationError("bad", reason=TokenValidationReason.MALFORMED), id="a refused token"),
            pytest.param(TokenExpiredError("old"), id="an expired token"),
        ],
    )
    def test_a_member_of_a_carrying_family_that_reads_no_code_reports_none(self, error: IdentityFetchError) -> None:
        """These take the attribute from the identity family, and no step on their path reads a code."""
        assert error.error_code == ""

    def test_token_endpoint_error_without_a_kind_is_unexpected(self) -> None:
        assert TokenEndpointError("boom").kind is FailureKind.UNEXPECTED

    @pytest.mark.parametrize(
        "code",
        [
            pytest.param("invalid_grant", id="a registered code"),
            pytest.param("slow_down", id="two words"),
            pytest.param("expired", id="one word"),
            pytest.param("insufficient_user_authentication", id="the longest registered code"),
            pytest.param("invalid_dpop_proof", id="a code with an initialism"),
            pytest.param("invalid_grant2", id="a digit in a later word"),
            pytest.param("a" * 64, id="the greatest length a code may have"),
        ],
    )
    def test_a_code_in_the_shape_a_code_takes_is_kept(self, code: str) -> None:
        assert TokenExchangeError("boom", kind=FailureKind.REJECTED, error_code=code).error_code == code

    @pytest.mark.parametrize(
        "code",
        [
            pytest.param("invalid code", id="a space"),
            pytest.param("Invalid_Grant", id="capitals"),
            pytest.param("the code you sent was already used", id="a sentence"),
            pytest.param("9f8c2a1b4e7d6039f8c2a1b4e7d60391", id="hex of sixteen bytes"),  # pragma: allowlist secret
            pytest.param("abcdefghijklmnopqrstuvwxyz234567", id="lowercase base32"),  # pragma: allowlist secret
            pytest.param("xY3-_aB", id="a URL-safe form"),
            pytest.param("_leading", id="a leading underscore"),
            pytest.param("trailing_", id="a trailing underscore"),
            pytest.param("a" * 65, id="longer than any code"),
            pytest.param("", id="empty"),
        ],
    )
    def test_a_value_of_another_shape_is_reported_as_absent(self, code: str) -> None:
        """The type owns this rule, so no raise site can put the endpoint's own text on a public error."""
        assert TokenExchangeError("boom", kind=FailureKind.REJECTED, error_code=code).error_code == ""

    def test_the_type_refuses_what_a_raise_site_would_have_published(self) -> None:
        """A raise that passed the endpoint's description straight through must not publish it."""
        description = "the refresh token 'rt-SECRET-xyz' is no longer valid"  # pragma: allowlist secret
        err = TokenRefreshError("HTTP 400", kind=FailureKind.REJECTED, error_code=description)
        assert err.error_code == ""
        assert "SECRET" not in str(err)


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


class TestIdentityErrors:
    """An identity failure reports a provider's error code the way a token-endpoint failure does."""

    def test_error_code_defaults_to_empty(self) -> None:
        assert IdentityFetchError("boom", kind=FailureKind.REJECTED).error_code == ""
        assert IdentityScopeNotGrantedError("boom").error_code == ""

    def test_error_code_stored_and_message_preserved(self) -> None:
        err = IdentityFetchError("Slack identity request failed", kind=FailureKind.REJECTED, error_code="invalid_auth")

        assert err.error_code == "invalid_auth"
        assert str(err) == "Slack identity request failed"

    def test_a_scope_refusal_carries_the_code_too(self) -> None:
        """The subclass names one condition, and the code says which of a provider's own it was."""
        err = IdentityScopeNotGrantedError("Slack identity request failed", error_code="missing_scope")

        assert err.error_code == "missing_scope"
        assert isinstance(err, IdentityFetchError)

    @pytest.mark.parametrize(
        "code",
        [
            pytest.param("Invalid_Auth", id="an upper case letter"),
            pytest.param("invalid auth", id="a space"),
            pytest.param("a" * 65, id="longer than any code"),
            pytest.param("", id="nothing at all"),
            pytest.param("<b>boom</b>", id="markup"),
        ],
    )
    def test_a_value_outside_the_shape_a_code_takes_is_reported_as_absent(self, code: str) -> None:
        """The member a code arrives in admits any text, so a value of another shape names no code."""
        assert IdentityFetchError("boom", kind=FailureKind.REJECTED, error_code=code).error_code == ""


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

    def test_an_error_code_cannot_be_changed_after_construction(self) -> None:
        err = TokenExchangeError("boom", kind=FailureKind.REJECTED, error_code="invalid_grant")
        with pytest.raises(AttributeError):
            err.error_code = "invalid_client"  # type: ignore[misc]

    def test_retryable_cannot_be_changed_on_a_member(self) -> None:
        with pytest.raises(AttributeError):
            FailureKind.TIMEOUT.retryable = False  # type: ignore[misc]


class TestExchangeIsNeverRetryable:
    @pytest.mark.parametrize("cls", NEVER_RETRYABLE_CLASSES)
    @pytest.mark.parametrize("kind", list(FailureKind))
    def test_a_phase_whose_request_is_never_repeated_is_not_retryable(
        self, cls: type[OAuthError], kind: FailureKind
    ) -> None:
        """The remedy for both is a new authorization, so neither may report that a retry would do."""
        err = cls("boom", kind=kind)
        assert err.kind is kind
        assert err.retryable is False

    def test_a_refresh_error_keeps_the_kind_rule(self) -> None:
        assert TokenRefreshError("boom", kind=FailureKind.SERVER_ERROR).retryable is True


class TestPickling:
    """Errors cross process boundaries in worker pools, so their classification must survive a round trip."""

    def test_a_token_endpoint_error_keeps_its_kind_and_code(self) -> None:
        err = TokenRefreshError("invalid_grant: gone", kind=FailureKind.REJECTED, error_code="invalid_grant")
        back = pickle.loads(pickle.dumps(err))
        assert type(back) is TokenRefreshError
        assert str(back) == "invalid_grant: gone"
        assert back.kind is FailureKind.REJECTED
        assert back.error_code == "invalid_grant"

    def test_an_authorization_response_error_keeps_its_kind_and_code(self) -> None:
        err = AuthorizationResponseError("refused", kind=FailureKind.REJECTED, error_code="access_denied")
        back = pickle.loads(pickle.dumps(err))
        assert type(back) is AuthorizationResponseError
        assert str(back) == "refused"
        assert back.kind is FailureKind.REJECTED
        assert back.error_code == "access_denied"
        assert back.retryable is False

    def test_a_validation_error_keeps_its_reason(self) -> None:
        err = TokenValidationError("bad signature", reason=TokenValidationReason.SIGNATURE)
        back = pickle.loads(pickle.dumps(err))
        assert type(back) is TokenValidationError
        assert back.reason is TokenValidationReason.SIGNATURE
        assert back.kind is FailureKind.REFUSED

    def test_an_expired_error_round_trips(self) -> None:
        back = pickle.loads(pickle.dumps(TokenExpiredError("old")))
        assert type(back) is TokenExpiredError
        assert back.reason is TokenValidationReason.EXPIRED
