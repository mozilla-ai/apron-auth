from __future__ import annotations

from any_auth.models import ProviderConfig
from any_auth.protocols import RevocationHandler


class TestLinearPreset:
    def test_returns_config_and_handler(self):
        from any_auth.providers.linear import preset

        config, handler = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_scope_separator_is_comma(self):
        from any_auth.providers.linear import preset

        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read", "write"])
        assert config.scope_separator == ","

    def test_config_has_correct_endpoints(self):
        from any_auth.providers.linear import preset

        config, _ = preset(client_id="lid", client_secret="lsecret", scopes=["read"])
        assert config.authorize_url == "https://linear.app/oauth/authorize"
        assert config.token_url == "https://api.linear.app/oauth/token"
        assert config.revocation_url == "https://api.linear.app/oauth/revoke"
