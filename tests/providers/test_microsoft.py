from __future__ import annotations

from apron_auth.models import ProviderConfig


class TestMicrosoftPreset:
    def test_returns_config_and_none_handler(self):
        from apron_auth.providers.microsoft import preset

        config, handler = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert isinstance(config, ProviderConfig)
        assert handler is None

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.authorize_url == "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        assert config.token_url == "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        assert config.revocation_url is None

    def test_extra_params_include_prompt(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(client_id="mid", client_secret="msecret", scopes=["offline_access"])
        assert config.extra_params["prompt"] == "consent"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.microsoft import BASE_SCOPES, preset

        config, _ = preset(
            client_id="mid",
            client_secret="msecret",  # pragma: allowlist secret
            scopes=["Mail.Read"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "Mail.Read" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.microsoft import preset

        config, _ = preset(
            client_id="mid",
            client_secret="msecret",  # pragma: allowlist secret
            scopes=["offline_access", "Mail.Read"],
        )
        assert config.scopes.count("offline_access") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.microsoft import BASE_SCOPES, preset

        config, _ = preset(
            client_id="mid",
            client_secret="msecret",  # pragma: allowlist secret
            scopes=["Mail.Read"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)
