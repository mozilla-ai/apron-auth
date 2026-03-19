from __future__ import annotations

from apron_auth.models import ProviderConfig


class TestTypeformPreset:
    def test_returns_config_and_none_handler(self):
        from apron_auth.providers.typeform import preset

        config, handler = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_pkce_disabled(self):
        from apron_auth.providers.typeform import preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        assert config.use_pkce is False

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.typeform import preset

        config, _ = preset(client_id="tid", client_secret="tsecret", scopes=["accounts:read"])
        assert config.authorize_url == "https://api.typeform.com/oauth/authorize"
        assert config.token_url == "https://api.typeform.com/oauth/token"
        assert config.revocation_url is None
