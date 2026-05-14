from __future__ import annotations

import pytest
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from apron_auth.errors import IdentityFetchError
from apron_auth.models import IdentityProfile, ProviderConfig, TenancyContext
from apron_auth.protocols import RevocationHandler

SLACK_AUTH_TEST_URL = "https://slack.com/api/auth.test"
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
            "https://slack.com/team_name": "Example Team",
            "https://slack.com/team_domain": "example",
        }
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity("user-token-abc", config)

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
        from apron_auth.providers.slack import SlackIdentityHandler, preset

        payload = {"ok": True, "sub": "U12345"}
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity("user-token-abc", config)

        assert identity.tenancies == ()

    async def test_team_id_present_but_team_name_and_domain_missing(self, httpx_mock: HTTPXMock) -> None:
        """``team_id`` is the canonical anchor — the entry is still
        emitted when ``team_name`` and ``team_domain`` are absent, with
        those fields surfacing as ``None``."""
        from apron_auth.providers.slack import SlackIdentityHandler, preset

        payload = {"ok": True, "https://slack.com/team_id": "T67890"}
        httpx_mock.add_response(url=SLACK_USERINFO_URL, json=payload)
        config, _ = preset(client_id="sid", client_secret="ssecret", scopes=["openid"])
        handler = SlackIdentityHandler()

        identity = await handler.fetch_identity("user-token-abc", config)

        assert identity.tenancies == (TenancyContext(id="T67890", name=None, domain=None),)
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

    def test_canonical_slack_host_without_openid_returns_handler(self) -> None:
        """Workspace-bot config (no openid in scopes) also gets the handler.

        The handler branches internally on ``openid`` presence, so
        resolution is purely host-based — the workspace-bot flow
        should reach :class:`SlackIdentityHandler` and use its
        ``team.info``/``auth.test`` path.
        """
        from apron_auth.providers.slack import SlackIdentityHandler, maybe_identity_handler, preset

        config, _ = preset(
            client_id="sid",
            client_secret="ssecret",  # pragma: allowlist secret
            scopes=["channels:read", "chat:write"],
        )
        assert isinstance(maybe_identity_handler(config), SlackIdentityHandler)

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
            await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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

        identity = await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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

        identity = await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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

        identity = await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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
            await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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

        identity = await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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

        identity = await handler.fetch_identity("xoxb-bot-token", self._bot_config())

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
            await handler.fetch_identity("xoxb-bot-token", self._bot_config())
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

        identity = await handler.fetch_identity("xoxb-bot-token", self._bot_config())

        assert identity.subject is None
        assert identity.email is None
        assert identity.email_verified is None
        assert identity.name is None
        assert identity.username is None
        assert identity.avatar_url is None


class TestSlackWorkspaceDomainParsing:
    """Domain extraction from an ``auth.test`` workspace URL host."""

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
