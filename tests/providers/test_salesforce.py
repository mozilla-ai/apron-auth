from __future__ import annotations

from apron_auth.models import ProviderConfig
from apron_auth.protocols import RevocationHandler
from apron_auth.providers.salesforce import preset


class TestSalesforcePreset:
    def test_returns_config_and_handler(self):
        from apron_auth.providers.salesforce import preset

        config, handler = preset(client_id="sfid", client_secret="sfsecret", scopes=["api"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from apron_auth.providers.salesforce import preset

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["api"])
        assert config.authorize_url == "https://login.salesforce.com/services/oauth2/authorize"
        assert config.token_url == "https://login.salesforce.com/services/oauth2/token"
        assert config.revocation_url == "https://login.salesforce.com/services/oauth2/revoke"

    def test_sandbox_host_produces_test_endpoints(self):
        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["api"],
            host="test.salesforce.com",
        )
        assert config.authorize_url == "https://test.salesforce.com/services/oauth2/authorize"
        assert config.token_url == "https://test.salesforce.com/services/oauth2/token"
        assert config.revocation_url == "https://test.salesforce.com/services/oauth2/revoke"

    def test_base_scopes_merged_with_caller_scopes(self):
        from apron_auth.providers.salesforce import BASE_SCOPES, preset

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["api"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "api" in config.scopes

    def test_duplicate_scopes_deduplicated(self):
        from apron_auth.providers.salesforce import preset

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["refresh_token", "api"],
        )
        assert config.scopes.count("refresh_token") == 1

    def test_scope_metadata_covers_base_scopes(self):
        from apron_auth.providers.salesforce import BASE_SCOPES, preset

        config, _ = preset(
            client_id="sfid",
            client_secret="sfsecret",  # pragma: allowlist secret
            scopes=["api"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)
