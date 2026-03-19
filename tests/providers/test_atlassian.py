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
