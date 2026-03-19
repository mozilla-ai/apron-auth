from __future__ import annotations

from any_auth.models import ProviderConfig


class TestMicrosoftPreset:
    def test_returns_config_and_none_handler(self):
        from any_auth.providers.microsoft import preset

        config, handler = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_config_has_correct_endpoints(self):
        from any_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.authorize_url == "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        assert config.token_url == "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        assert config.revocation_url is None

    def test_extra_params_include_prompt(self):
        from any_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.extra_params["prompt"] == "consent"
