from __future__ import annotations

from pydantic import SecretStr

from apron_auth.models import ProviderConfig
from apron_auth.providers._host_match import matches_suffix, oauth_hosts_match


def _make_config(authorize_url: str, token_url: str) -> ProviderConfig:
    return ProviderConfig(
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url=authorize_url,
        token_url=token_url,
    )


class TestMatchesSuffix:
    def test_empty_host_does_not_match(self):
        assert matches_suffix("", ("example.com",)) is False

    def test_exact_match_returns_true(self):
        assert matches_suffix("example.com", ("example.com",)) is True

    def test_label_boundary_subdomain_matches(self):
        assert matches_suffix("api.example.com", ("example.com",)) is True

    def test_lookalike_with_shared_tld_does_not_match(self):
        assert matches_suffix("evilexample.com", ("example.com",)) is False

    def test_multiple_suffixes_any_match(self):
        assert matches_suffix("graph.microsoft.com", ("salesforce.com", "graph.microsoft.com")) is True

    def test_no_suffixes_never_matches(self):
        assert matches_suffix("example.com", ()) is False

    def test_substring_after_dot_does_not_match(self):
        assert matches_suffix("attacker.com.example.com.attacker.test", ("example.com",)) is False

    def test_unrelated_host_does_not_match(self):
        assert matches_suffix("other.test", ("example.com",)) is False


class TestOauthHostsMatch:
    def test_both_urls_matching_returns_true(self):
        config = _make_config(
            authorize_url="https://api.example.com/authorize",
            token_url="https://api.example.com/token",
        )
        assert oauth_hosts_match(config, ("example.com",)) is True

    def test_both_urls_unrelated_returns_false(self):
        config = _make_config(
            authorize_url="https://other.test/authorize",
            token_url="https://other.test/token",
        )
        assert oauth_hosts_match(config, ("example.com",)) is False

    def test_distinct_subdomains_both_matching_returns_true(self):
        config = _make_config(
            authorize_url="https://auth.example.com/authorize",
            token_url="https://api.example.com/token",
        )
        assert oauth_hosts_match(config, ("example.com",)) is True

    def test_only_authorize_url_matching_returns_false(self):
        config = _make_config(
            authorize_url="https://api.example.com/authorize",
            token_url="https://attacker.test/token",
        )
        assert oauth_hosts_match(config, ("example.com",)) is False

    def test_only_token_url_matching_returns_false(self):
        config = _make_config(
            authorize_url="https://attacker.test/authorize",
            token_url="https://api.example.com/token",
        )
        assert oauth_hosts_match(config, ("example.com",)) is False
