from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import (
    ConfigurationError,
    FailureKind,
    IdentityFetchError,
    IdentityScopeNotGrantedError,
    RevocationError,
)
from apron_auth.models import IdentityMaterial, IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler

SLACK_AUTH_TEST_URL = "https://slack.com/api/auth.test"
SLACK_REVOKE_URL = "https://slack.com/api/auth.revoke"
SLACK_TEAM_INFO_URL = "https://slack.com/api/team.info"
SLACK_USERINFO_URL = "https://slack.com/api/openid.connect.userInfo"


class TestSlackConsentPickerInvariant:
    """The set-level constraint must be enforceable from ProviderConfig
    fields alone — a generic consent picker validates a Slack scope
    selection without any Slack-specific knowledge.
    """

    @staticmethod
    def _families_satisfied(selected: set[str], families: list[list[str]]) -> bool:
        """Generic at-least-one-of-some-family check — no provider knowledge."""
        if not families:
            return True
        return any(any(scope in selected for scope in family) for family in families)

    def test_empty_selection_fails_every_required_family(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read", "chat:write"],
            user_scopes=["users:read"],
        )
        assert not self._families_satisfied(set(), config.required_scope_families)

    def test_one_bot_scope_satisfies_constraint(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read", "chat:write"],
            user_scopes=["users:read"],
        )
        assert self._families_satisfied({"channels:read"}, config.required_scope_families)

    def test_only_user_scope_satisfies_constraint(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read"],
        )
        assert self._families_satisfied({"users:read"}, config.required_scope_families)

    def test_unrelated_scope_does_not_satisfy_constraint(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read"],
        )
        assert not self._families_satisfied({"unrelated:scope"}, config.required_scope_families)


class TestSlackIdentityHandler:
    async def test_happy_path_maps_userinfo_fields(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        payload = {
            "ok": True,
            "sub": "U12345",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Slack User",
            "picture": "https://example.com/avatar.png",
            "https://slack.com/user_id": "U12345",
            "https://slack.com/team_id": "T67890",
            "https://slack.com/team_name": "Example Team",
            "https://slack.com/team_domain": "example",
        }
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)

        assert identity == IdentityProfile(
            provider="slack",
            subject="U12345",
            email="user@example.com",
            email_verified=True,
            name="Slack User",
            username="U12345",
            avatar_url="https://example.com/avatar.png",
            tenancies=(
                TenancyContext(
                    id="T67890",
                    name="Example Team",
                    domain="example",
                ),
            ),
            raw=payload,
        )

    async def test_missing_team_id_yields_empty_tenancies(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        payload = {"ok": True, "sub": "U12345"}
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)

        assert identity.tenancies == ()

    async def test_team_id_present_but_team_name_and_domain_missing(self, httpx_mock: HTTPXMock) -> None:
        """``team_id`` is the canonical anchor — the entry is still
        emitted when ``team_name`` and ``team_domain`` are absent, with
        those fields surfacing as ``None``."""
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        payload = {"ok": True, "https://slack.com/team_id": "T67890"}
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)

        assert identity.tenancies == (TenancyContext(id="T67890", name=None, domain=None),)
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.headers.get("authorization") == "Bearer user-token-abc"

    async def test_http_error_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        httpx_mock.add_response(url=SLACK_USERINFO_URL, status_code=500, json={"error": "internal"})
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Slack identity"):
            await handler.fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        httpx_mock.add_response(url=SLACK_USERINFO_URL, status_code=200, content=b"not-json")
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Slack identity response"):
            await handler.fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)

    async def test_ok_false_in_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        httpx_mock.add_response(
            url=SLACK_USERINFO_URL,
            status_code=200,
            json={"ok": False, "error": "invalid_auth"},
        )
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="invalid_auth") as exc_info:
            await handler.fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)
        assert exc_info.value.kind is FailureKind.REJECTED

    @pytest.mark.parametrize(
        "error", ["fatal_error", "internal_error", "ratelimited", "request_timeout", "service_unavailable"]
    )
    async def test_ok_false_with_a_transient_error_is_retryable(self, httpx_mock: HTTPXMock, error: str) -> None:
        """Slack reports its own outages and rate limits as 200 with ok=false, so they stay retryable."""
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        httpx_mock.add_response(url=SLACK_USERINFO_URL, status_code=200, json={"ok": False, "error": error})
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")

        with pytest.raises(IdentityFetchError, match=error) as exc_info:
            await SlackIdentityHandler().fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)
        assert exc_info.value.kind is FailureKind.SERVER_ERROR
        assert exc_info.value.retryable is True

    async def test_ok_false_missing_scope_raises_scope_not_granted(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        httpx_mock.add_response(
            url=SLACK_USERINFO_URL,
            status_code=200,
            json={"ok": False, "error": "missing_scope"},
        )
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")

        with pytest.raises(IdentityScopeNotGrantedError, match="missing_scope"):
            await SlackIdentityHandler().fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)

    async def test_ok_false_other_error_is_not_scope_not_granted(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, sign_in_preset

        httpx_mock.add_response(
            url=SLACK_USERINFO_URL,
            status_code=200,
            json={"ok": False, "error": "invalid_auth"},
        )
        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret")

        with pytest.raises(IdentityFetchError) as exc_info:
            await SlackIdentityHandler().fetch_identity(IdentityMaterial(access_token="user-token-abc"), config)
        assert not isinstance(exc_info.value, IdentityScopeNotGrantedError)


class TestSlackSignInFlowDetection:
    """Telling the Sign in with Slack flow from a workspace install."""

    def test_the_sign_in_token_endpoint_selects_the_sign_in_flow(self) -> None:
        from apron_auth.providers.slack import _is_sign_in_flow, sign_in_preset

        config, _ = sign_in_preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["email"],
        )
        assert _is_sign_in_flow(config) is True

    def test_the_install_token_endpoint_selects_the_workspace_flow(self) -> None:
        from apron_auth.providers.slack import _is_sign_in_flow, preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
        )
        assert _is_sign_in_flow(config) is False

    def test_a_scope_word_alone_does_not_select_the_sign_in_flow(self) -> None:
        """The install endpoint returns no ID token, so no scope word can make its token a person's."""
        from apron_auth.providers.slack import _is_sign_in_flow

        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://slack.com/oauth/v2/authorize",
            token_url="https://slack.com/api/oauth.v2.access",
            scopes=["channels:read"],
            extra_params={"user_scope": "openid profile"},
        )

        assert _is_sign_in_flow(config) is False


class TestSlackPreset:
    def test_raises_when_bot_and_user_scopes_are_empty(self):
        from apron_auth.providers.slack import preset

        with pytest.raises(ValueError, match="at least one scope"):
            preset(client_id="sid", client_secret="ssecret", scopes=[], user_scopes=[])

    def test_returns_config_and_handler(self):
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        assert config.authorize_url == "https://slack.com/oauth/v2/authorize"
        assert config.token_url == "https://slack.com/api/oauth.v2.access"
        assert config.revocation_url == "https://slack.com/api/auth.revoke"

    def test_scope_separator_is_comma(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read", "chat:write"])
        assert config.scope_separator == ","

    def test_user_scopes_added_to_extra_params(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read", "channels:history"],
        )
        assert config.extra_params["user_scope"] == "users:read,channels:history"

    def test_user_scopes_omitted_when_none(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
        )
        assert "user_scope" not in config.extra_params

    def test_user_scopes_coexist_with_extra_params(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read"],
            extra_params={"team": "T123"},
        )
        assert config.extra_params["user_scope"] == "users:read"
        assert config.extra_params["team"] == "T123"

    def test_user_scopes_takes_precedence_over_extra_params(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read"],
            extra_params={"user_scope": "should_be_overridden", "team": "T123"},
        )
        assert config.extra_params["user_scope"] == "users:read"
        assert config.extra_params["team"] == "T123"

    def test_bot_scopes_only_declares_single_required_family(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read", "chat:write"],
        )
        assert config.required_scope_families == [["channels:read", "chat:write"]]

    def test_bot_and_user_scopes_declare_two_required_families(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["users:read", "channels:history"],
        )
        assert config.required_scope_families == [
            ["channels:read"],
            ["users:read", "channels:history"],
        ]

    def test_empty_user_scopes_omitted_from_required_families(self):
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=[],
        )
        assert config.required_scope_families == [["channels:read"]]


class TestSlackSignInPreset:
    """The Sign in with Slack preset, which Slack serves from its OpenID endpoints."""

    def test_config_has_the_openid_endpoints(self) -> None:
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret", scopes=["email"])
        assert config.authorize_url == "https://slack.com/openid/connect/authorize"
        assert config.token_url == "https://slack.com/api/openid.connect.token"
        assert config.revocation_url == "https://slack.com/api/auth.revoke"

    def test_config_names_the_issuer_slack_states(self) -> None:
        """An ID token's issuer cannot be checked against an issuer the config does not name."""
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret", scopes=["email"])
        assert config.issuer == "https://slack.com"

    def test_returns_config_and_handler(self) -> None:
        from apron_auth.providers.slack import sign_in_preset

        config, handler = sign_in_preset(client_id="sid", client_secret="ssecret", scopes=["email"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    @pytest.mark.parametrize(
        ("scopes", "expected"),
        [
            pytest.param([], ["openid"], id="no scopes given"),
            pytest.param(["email"], ["openid", "email"], id="openid added in front"),
            pytest.param(["openid", "email"], ["openid", "email"], id="openid already first"),
            pytest.param(["email", "openid"], ["email", "openid"], id="openid already present"),
        ],
    )
    def test_openid_is_always_requested(self, scopes: list[str], expected: list[str]) -> None:
        """Slack returns an ID token only for a request that asks for openid."""
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret", scopes=scopes)
        assert config.scopes == expected

    def test_the_requested_scopes_are_one_required_family(self) -> None:
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret", scopes=["email", "profile"])
        assert config.required_scope_families == [["openid", "email", "profile"]]

    def test_no_user_scope_parameter_is_sent(self) -> None:
        """Slack splits bot and user scopes only on its install endpoint."""
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(client_id="sid", client_secret="ssecret", scopes=["email"])
        assert "user_scope" not in config.extra_params

    def test_extra_params_are_kept(self) -> None:
        from apron_auth.providers.slack import sign_in_preset

        config, _ = sign_in_preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["email"],
            extra_params={"team": "T123"},
        )
        assert config.extra_params["team"] == "T123"

    def test_extra_params_cannot_replace_the_requested_scopes(self) -> None:
        """A scope parameter of the caller's would drop openid, and then no ID token is required."""
        from apron_auth.providers.slack import sign_in_preset

        with pytest.raises(ValueError, match="extra_params cannot set scope"):
            sign_in_preset(
                client_id="sid",
                client_secret="ssecret",  # pragma: allowlist secret
                scopes=["email"],
                extra_params={"scope": "email"},
            )


class TestSlackInstallPresetRefusesTheSignInScope:
    """A workspace install and Sign in with Slack are separate flows at Slack."""

    @pytest.mark.parametrize(
        ("scopes", "user_scopes"),
        [
            pytest.param(["openid"], None, id="in the bot scopes"),
            pytest.param(["channels:read", "openid"], None, id="beside a bot scope"),
            pytest.param(["channels:read"], ["openid"], id="in the user scopes"),
            pytest.param(["channels:read"], ["profile", "openid"], id="beside a user scope"),
        ],
    )
    def test_openid_is_refused(self, scopes: list[str], user_scopes: list[str] | None) -> None:
        from apron_auth.providers.slack import preset

        with pytest.raises(ValueError, match="openid"):
            preset(
                client_id="sid",
                client_secret="ssecret",  # pragma: allowlist secret
                scopes=scopes,
                user_scopes=user_scopes,
            )

    def test_openid_in_the_user_scope_extra_param_is_refused(self) -> None:
        """A caller can set user_scope directly, which is where the preset puts user scopes too."""
        from apron_auth.providers.slack import preset

        with pytest.raises(ValueError, match="openid"):
            preset(
                client_id="sid",
                client_secret="ssecret",  # pragma: allowlist secret
                scopes=["channels:read"],
                extra_params={"user_scope": "openid,profile"},
            )

    def test_the_user_scope_extra_param_is_read_with_the_declared_separator(self) -> None:
        from apron_auth.providers.slack import preset

        with pytest.raises(ValueError, match="openid"):
            preset(
                client_id="sid",
                client_secret="ssecret",  # pragma: allowlist secret
                scopes=["channels:read"],
                extra_params={"user_scope": "profile openid"},
            )

    def test_a_scope_entry_holding_several_words_is_read_word_by_word(self) -> None:
        """The client reads the built scope parameter word by word, so this refusal does too."""
        from apron_auth.providers.slack import preset

        with pytest.raises(ValueError, match="openid"):
            preset(
                client_id="sid",
                client_secret="ssecret",  # pragma: allowlist secret
                scopes=["channels:read openid"],
            )

    def test_extra_params_cannot_replace_the_requested_scopes(self) -> None:
        """A scope parameter of the caller's would replace the bot scopes, openid included."""
        from apron_auth.providers.slack import preset

        with pytest.raises(ValueError, match="extra_params cannot set scope"):
            preset(
                client_id="sid",
                client_secret="ssecret",  # pragma: allowlist secret
                scopes=["channels:read"],
                extra_params={"scope": "channels:read,openid"},
            )

    def test_a_scope_that_merely_contains_openid_is_kept(self) -> None:
        """Only the scope word itself is the sign-in scope."""
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["openid:read"],
        )
        assert config.scopes == ["openid:read"]


class TestSlackFlowMismatchIsRefused:
    """The token endpoint and the requested scopes must name the same Slack flow."""

    @staticmethod
    def _handler_and_material() -> tuple[object, IdentityMaterial]:
        from apron_auth.providers.slack import SlackIdentityHandler

        return SlackIdentityHandler(), IdentityMaterial(access_token="token-abc")

    async def test_the_sign_in_endpoint_without_the_sign_in_scope_is_refused(self) -> None:
        """Without openid Slack returns no ID token, so no nonce is sent and no person is verified."""
        handler, material = self._handler_and_material()
        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://slack.com/openid/connect/authorize",
            token_url="https://slack.com/api/openid.connect.token",
            scopes=["email"],
        )

        with pytest.raises(ConfigurationError, match="must ask for the openid scope"):
            await handler.fetch_identity(material, config)

    @pytest.mark.parametrize(
        ("scopes", "extra_params"),
        [
            pytest.param(["openid"], {}, id="in the scope parameter"),
            pytest.param(["channels:read"], {"user_scope": "openid"}, id="in the user_scope parameter"),
            pytest.param(
                ["channels:read"],
                {"user_scope": "profile,openid"},
                id="comma separated under a config that joins with a space",
            ),
        ],
    )
    async def test_the_install_endpoint_with_the_sign_in_scope_is_refused(
        self, scopes: list[str], extra_params: dict[str, str]
    ) -> None:
        """The install endpoint returns no ID token, so a person identity from it is unverified."""
        handler, material = self._handler_and_material()
        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://slack.com/oauth/v2/authorize",
            token_url="https://slack.com/api/oauth.v2.access",
            scopes=scopes,
            extra_params=extra_params,
        )

        with pytest.raises(ConfigurationError, match="must name Slack's OpenID token endpoint"):
            await handler.fetch_identity(material, config)


class TestSlackRevocationHandler:
    async def test_revokes_via_authorization_header(self, httpx_mock: HTTPXMock) -> None:
        """Slack rejects query-string tokens for apps created after
        2021-02-24, so the request sends the token in the
        ``Authorization: Bearer`` header via POST, never in the URL."""
        httpx_mock.add_response(url=SLACK_REVOKE_URL, json={"ok": True, "revoked": True})
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        result = await handler.revoke("xoxb-access-abc", config)

        assert result is True
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.headers.get("authorization") == "Bearer xoxb-access-abc"
        assert request.url.params.get("token") is None
        assert "xoxb-access-abc" not in str(request.url)

    async def test_ok_false_returns_false(self, httpx_mock: HTTPXMock) -> None:
        """A 2xx body with ``ok=false`` is a failed revocation, returned
        as ``False`` for the client to surface as ``RevocationError``."""
        httpx_mock.add_response(url=SLACK_REVOKE_URL, json={"ok": False, "error": "invalid_auth"})
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        result = await handler.revoke("xoxb-access-abc", config)
        assert result is False

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        with pytest.raises(RevocationError, match="^Failed to revoke Slack token: network error$") as exc_info:
            await handler.revoke("access-abc", config)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_malformed_json_response_raises_revocation_error(self, httpx_mock: HTTPXMock):
        """A 2xx body that is not valid JSON must surface as ``RevocationError``,
        not an unwrapped ``json.JSONDecodeError``."""
        httpx_mock.add_response(status_code=200, content=b"not json")
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        with pytest.raises(RevocationError) as exc_info:
            await handler.revoke("access-abc", config)
        assert str(exc_info.value) == "Failed to parse Slack revocation response"
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_invalid_revocation_url_raises_revocation_error(self, httpx_mock: HTTPXMock) -> None:
        """A validated config refuses such a URL, so this holds the handler to its own guard."""
        httpx_mock.add_response(is_optional=True)
        from apron_auth.providers.slack import SlackRevocationHandler

        config = ProviderConfig.model_construct(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://slack.com/oauth/v2/authorize",
            token_url="https://slack.com/api/oauth.v2.access",
            revocation_url="https://slack.com/api/auth.revoke\x00",
        )
        handler = SlackRevocationHandler()
        with pytest.raises(RevocationError, match="^Failed to revoke Slack token: invalid URL$") as exc_info:
            await handler.revoke("access-abc", config)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize(
        "body",
        [{"ok": "false"}, {"ok": "true"}, {"ok": 1}, {"ok": None}, {}],
        ids=["string-false", "string-true", "int-one", "null", "missing"],
    )
    async def test_ok_that_is_not_true_returns_false(self, body: dict[str, object], httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=SLACK_REVOKE_URL, json=body)
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        assert await handler.revoke("access-abc", config) is False

    async def test_deeply_nested_response_raises_revocation_error(self, httpx_mock: HTTPXMock) -> None:
        # The depth is far past any interpreter's JSON nesting limit, so decoding raises RecursionError.
        httpx_mock.add_response(url=SLACK_REVOKE_URL, status_code=200, content=b"[" * 100_000 + b"]" * 100_000)
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        with pytest.raises(RevocationError, match="^Failed to parse Slack revocation response$") as exc_info:
            await handler.revoke("access-abc", config)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_non_object_response_raises_revocation_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=SLACK_REVOKE_URL, json=["ok"])
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        with pytest.raises(RevocationError, match="^Slack revocation response was not a JSON object$") as exc_info:
            await handler.revoke("access-abc", config)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_error_status_returns_false(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=SLACK_REVOKE_URL, status_code=500, json={"ok": True})
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        assert await handler.revoke("access-abc", config) is False


class TestSlackWorkspaceBotIdentity:
    """``SlackIdentityHandler`` branch for tokens without ``openid``.

    Workspace-bot tokens carry no person identity, so ``subject`` /
    ``email`` / ``name`` / ``username`` / ``avatar_url`` stay ``None``
    by design. Tenancy is fetched from ``team.info`` (preferred,
    requires ``team:read``) or ``auth.test`` (universal fallback when
    ``team:read`` was not granted).
    """

    @staticmethod
    def _bot_config() -> ProviderConfig:
        from apron_auth.providers.slack import preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read", "chat:write"],
        )
        return config

    async def test_auth_test_failure_after_fallback_raises(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler

        httpx_mock.add_response(
            url=SLACK_TEAM_INFO_URL,
            json={"ok": False, "error": "missing_scope"},
        )
        httpx_mock.add_response(
            url=SLACK_AUTH_TEST_URL,
            json={"ok": False, "error": "token_revoked"},
        )
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="auth.test.*token_revoked"):
            await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

    async def test_auth_test_url_with_unrecognised_host_yields_no_domain(self, httpx_mock: HTTPXMock) -> None:
        """Unrecognisable workspace URL → ``domain=None`` rather than a guess."""
        from apron_auth.providers.slack import SlackIdentityHandler

        httpx_mock.add_response(
            url=SLACK_TEAM_INFO_URL,
            json={"ok": False, "error": "missing_scope"},
        )
        auth_test_payload = {
            "ok": True,
            "url": "https://example.org/",
            "team": "Krane Flannel",
            "team_id": "T67890",
        }
        httpx_mock.add_response(url=SLACK_AUTH_TEST_URL, json=auth_test_payload)
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

        assert identity.tenancies == (
            TenancyContext(
                id="T67890",
                name="Krane Flannel",
                domain=None,
                raw=auth_test_payload,
            ),
        )

    async def test_enterprise_grid_yields_single_tenancy(self, httpx_mock: HTTPXMock) -> None:
        """Enterprise Grid info flows through ``raw``, not into extra tenancies.

        Locks the deferred multi-team contract: a future expansion to
        one ``TenancyContext`` per accessible team must update this
        test rather than quietly invalidating the single-tenant
        assumption.
        """
        from apron_auth.providers.slack import SlackIdentityHandler

        team = {
            "id": "T67890",
            "name": "Example Team",
            "domain": "example",
            "enterprise_id": "E12345",
            "enterprise_name": "Example Enterprise",
        }
        payload = {"ok": True, "team": team}
        httpx_mock.add_response(url=SLACK_TEAM_INFO_URL, json=payload)
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

        assert len(identity.tenancies) == 1
        assert identity.tenancies[0].raw == team
        assert identity.tenancies[0].raw["enterprise_id"] == "E12345"
        assert identity.tenancies[0].raw["enterprise_name"] == "Example Enterprise"

    async def test_team_info_happy_path_populates_tenancy(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler

        team = {
            "id": "T67890",
            "name": "Example Team",
            "domain": "example",
        }
        payload = {"ok": True, "team": team}
        httpx_mock.add_response(url=SLACK_TEAM_INFO_URL, json=payload)
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

        assert identity == IdentityProfile(
            provider="slack",
            tenancies=(
                TenancyContext(
                    id="T67890",
                    name="Example Team",
                    domain="example",
                    raw=team,
                ),
            ),
            raw=payload,
        )
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.headers.get("authorization") == "Bearer xoxb-bot-token"

    async def test_team_info_http_error_raises(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler

        httpx_mock.add_response(url=SLACK_TEAM_INFO_URL, status_code=500, json={"error": "internal"})
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="team.info"):
            await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

    async def test_team_info_missing_scope_falls_back_to_auth_test(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler

        httpx_mock.add_response(
            url=SLACK_TEAM_INFO_URL,
            json={"ok": False, "error": "missing_scope"},
        )
        auth_test_payload = {
            "ok": True,
            "url": "https://kraneflannel.slack.com/",
            "team": "Krane Flannel",
            "team_id": "T67890",
            "user": "bot-user",
            "user_id": "U12345",
            "bot_id": "B12345",
        }
        httpx_mock.add_response(url=SLACK_AUTH_TEST_URL, json=auth_test_payload)
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

        assert identity == IdentityProfile(
            provider="slack",
            tenancies=(
                TenancyContext(
                    id="T67890",
                    name="Krane Flannel",
                    domain="kraneflannel",
                    raw=auth_test_payload,
                ),
            ),
            raw=auth_test_payload,
        )

    async def test_team_info_missing_team_object_yields_empty_tenancies(self, httpx_mock: HTTPXMock) -> None:
        """``ok=true`` without a nested ``team`` object → no tenancy emitted."""
        from apron_auth.providers.slack import SlackIdentityHandler

        payload = {"ok": True}
        httpx_mock.add_response(url=SLACK_TEAM_INFO_URL, json=payload)
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

        assert identity.tenancies == ()
        assert identity.raw == payload

    async def test_team_info_non_missing_scope_error_does_not_fall_back(self, httpx_mock: HTTPXMock) -> None:
        """Real auth errors must surface, not be papered over by ``auth.test``."""
        from apron_auth.providers.slack import SlackIdentityHandler

        httpx_mock.add_response(
            url=SLACK_TEAM_INFO_URL,
            json={"ok": False, "error": "invalid_auth"},
        )
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="team.info.*invalid_auth"):
            await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())
        # Only the team.info request should have been made; pytest-httpx
        # otherwise fails on unused queued responses, so a missing
        # ``auth.test`` queue is itself the assertion that no fallback
        # request was attempted.
        assert [str(r.url) for r in httpx_mock.get_requests()] == [SLACK_TEAM_INFO_URL]

    async def test_workspace_bot_path_leaves_person_fields_none(self, httpx_mock: HTTPXMock) -> None:
        """Person-identity fields are deliberately ``None`` (see handler docstring)."""
        from apron_auth.providers.slack import SlackIdentityHandler

        team = {"id": "T67890", "name": "Example", "domain": "example"}
        payload = {"ok": True, "team": team}
        httpx_mock.add_response(url=SLACK_TEAM_INFO_URL, json=payload)
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="xoxb-bot-token"), self._bot_config())

        assert identity.subject is None
        assert identity.email is None
        assert identity.email_verified is None
        assert identity.name is None
        assert identity.username is None
        assert identity.avatar_url is None


class TestSlackWorkspaceDomainParsing:
    """Domain extraction from an ``auth.test`` workspace URL host."""

    def test_the_workspace_host_suffix_agrees_with_the_member(self) -> None:
        from apron_auth.models import Provider
        from apron_auth.providers.slack import _SLACK_HOST_SUFFIX

        assert f".{Provider.SLACK.host_suffixes[0]}" == _SLACK_HOST_SUFFIX

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://kraneflannel.slack.com/", "kraneflannel"),
            ("https://kraneflannel.slack.com", "kraneflannel"),
            ("http://kraneflannel.slack.com/path", "kraneflannel"),
            (None, None),
            ("", None),
            ("not a url", None),
            ("https://example.com/", None),
            ("https://slack.com/", None),
            # Enterprise Grid org URLs (``*.enterprise.slack.com``) are
            # multi-segment and intentionally fall through to ``None``
            # — there is no single workspace ``team_domain`` to surface.
            ("https://myorg.enterprise.slack.com/", None),
        ],
    )
    def test_parse_team_domain_from_url(self, url: str | None, expected: str | None) -> None:
        from apron_auth.providers.slack import _parse_team_domain_from_url

        assert _parse_team_domain_from_url(url) == expected
