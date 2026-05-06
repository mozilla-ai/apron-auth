from __future__ import annotations

import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig
from apron_auth.protocols import RevocationHandler

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
        from apron_auth.providers.slack import SlackIdentityHandler, preset

        payload = {
            "ok": True,
            "sub": "U12345",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Slack User",
            "picture": "https://example.com/avatar.png",
            "https://slack.com/user_id": "U12345",
            "https://slack.com/team_id": "T67890",
        }
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity("user-token-abc", config)

        assert identity == IdentityProfile(
            subject="U12345",
            email="user@example.com",
            email_verified=True,
            name="Slack User",
            username="U12345",
            avatar_url="https://example.com/avatar.png",
            raw=payload,
        )
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.headers.get("authorization") == "Bearer user-token-abc"

    async def test_http_error_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, preset

        httpx_mock.add_response(url=SLACK_USERINFO_URL, status_code=500, json={"error": "internal"})
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to fetch Slack identity"):
            await handler.fetch_identity("user-token-abc", config)

    async def test_non_json_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, preset

        httpx_mock.add_response(url=SLACK_USERINFO_URL, status_code=200, content=b"not-json")
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="Failed to parse Slack identity response"):
            await handler.fetch_identity("user-token-abc", config)

    async def test_ok_false_in_2xx_raises_identity_fetch_error(self, httpx_mock: HTTPXMock) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, preset

        httpx_mock.add_response(
            url=SLACK_USERINFO_URL,
            status_code=200,
            json={"ok": False, "error": "invalid_auth"},
        )
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        with pytest.raises(IdentityFetchError, match="invalid_auth"):
            await handler.fetch_identity("user-token-abc", config)


class TestSlackMaybeIdentityHandler:
    def test_canonical_slack_host_with_openid_returns_handler(self) -> None:
        from apron_auth.providers.slack import SlackIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = maybe_identity_handler(config)
        assert isinstance(handler, SlackIdentityHandler)

    def test_canonical_slack_host_without_openid_returns_none(self) -> None:
        """Workspace-bot config (no openid in scopes) → no handler."""
        from apron_auth.providers.slack import maybe_identity_handler, preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read", "chat:write"],
        )
        assert maybe_identity_handler(config) is None

    def test_lookalike_host_returns_none(self) -> None:
        from apron_auth.providers.slack import maybe_identity_handler

        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://slack.com.attacker.test/oauth/v2/authorize",
            token_url="https://slack.com.attacker.test/api/oauth.v2.access",
            scopes=["openid"],
        )
        assert maybe_identity_handler(config) is None

    def test_non_slack_host_returns_none(self) -> None:
        from apron_auth.providers.slack import maybe_identity_handler

        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            scopes=["openid"],
        )
        assert maybe_identity_handler(config) is None

    def test_only_authorize_url_matching_returns_none(self) -> None:
        from apron_auth.providers.slack import maybe_identity_handler

        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://slack.com/oauth/v2/authorize",
            token_url="https://attacker.example.com/api/oauth.v2.access",
            scopes=["openid"],
        )
        assert maybe_identity_handler(config) is None

    def test_only_token_url_matching_returns_none(self) -> None:
        from apron_auth.providers.slack import maybe_identity_handler

        config = ProviderConfig(
            client_id="sid",
            client_secret=SecretStr("ssecret"),  # pragma: allowlist secret
            authorize_url="https://attacker.example.com/oauth/v2/authorize",
            token_url="https://slack.com/api/oauth.v2.access",
            scopes=["openid"],
        )
        assert maybe_identity_handler(config) is None

    def test_openid_via_user_scope_returns_handler(self) -> None:
        """Combined bot+SiwS install: openid travels in ``user_scope``."""
        from apron_auth.providers.slack import SlackIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read"],
            user_scopes=["openid", "profile", "email"],
        )
        handler = maybe_identity_handler(config)
        assert isinstance(handler, SlackIdentityHandler)


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


class TestSlackRevocationHandler:
    async def test_revokes_via_get(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(json={"ok": True, "revoked": True})
        from apron_auth.providers.slack import preset

        config, handler = preset(client_id="sid", client_secret="ssecret", scopes=["channels:read"])
        result = await handler.revoke("access-abc", config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "GET"
        assert "token=access-abc" in str(request.url)
