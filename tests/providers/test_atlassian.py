from __future__ import annotations

from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler


class TestAtlassianPreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.atlassian import preset

        config, handler = preset(client_id="aid", client_secret="asecret", scopes=["read:jira-work"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.atlassian import preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:jira-work"])
        assert config.authorize_url == "https://auth.atlassian.com/authorize"
        assert config.token_url == "https://auth.atlassian.com/oauth/token"
        assert config.revocation_url == "https://auth.atlassian.com/oauth/revoke"

    def test_extra_params_include_audience(self):
        from apron_auth.providers.atlassian import preset

        config, _ = preset(client_id="aid", client_secret="asecret", scopes=["read:jira-work"])
        assert config.extra_params["audience"] == "api.atlassian.com"
        assert config.extra_params["prompt"] == "consent"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.atlassian import BASE_SCOPES, preset

        config, _ = preset(
            client_id="aid",
            client_secret="asecret",  # pragma: allowlist secret
            scopes=["read:jira-work"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "read:jira-work" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.atlassian import preset

        config, _ = preset(
            client_id="aid",
            client_secret="asecret",  # pragma: allowlist secret
            scopes=["offline_access", "read:jira-work"],
        )
        assert config.scopes.count("offline_access") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.atlassian import BASE_SCOPES, preset

        config, _ = preset(
            client_id="aid",
            client_secret="asecret",  # pragma: allowlist secret
            scopes=["read:jira-work"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)
