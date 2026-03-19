from __future__ import annotations

from any_auth.models import ProviderConfig


class TestNotionPreset:
    def test_returns_config_and_none_handler(self):
        from any_auth.providers.notion import preset

        config, handler = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_uses_client_secret_basic(self):
        from any_auth.providers.notion import preset

        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.token_endpoint_auth_method == "client_secret_basic"

    def test_config_has_correct_endpoints(self):
        from any_auth.providers.notion import preset

        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.authorize_url == "https://api.notion.com/v1/oauth/authorize"
        assert config.token_url == "https://api.notion.com/v1/oauth/token"
        assert config.revocation_url is None

    def test_extra_params_include_owner(self):
        from any_auth.providers.notion import preset

        config, _ = preset(client_id="nid", client_secret="nsecret", scopes=[])
        assert config.extra_params["owner"] == "user"
