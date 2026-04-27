from __future__ import annotations

from pytest_httpx import HTTPXMock

from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestSlackPreset:
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
