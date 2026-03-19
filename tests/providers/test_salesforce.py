from __future__ import annotations

from any_auth.models import ProviderConfig
from any_auth.protocols import RevocationHandler


class TestSalesforcePreset:
    def test_returns_config_and_handler(self):
        from any_auth.providers.salesforce import preset

        config, handler = preset(client_id="sfid", client_secret="sfsecret", scopes=["api"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(handler, RevocationHandler)

    def test_config_has_correct_endpoints(self):
        from any_auth.providers.salesforce import preset

        config, _ = preset(client_id="sfid", client_secret="sfsecret", scopes=["api"])
        assert config.authorize_url == "https://login.salesforce.com/services/oauth2/authorize"
        assert config.token_url == "https://login.salesforce.com/services/oauth2/token"
        assert config.revocation_url == "https://login.salesforce.com/services/oauth2/revoke"
