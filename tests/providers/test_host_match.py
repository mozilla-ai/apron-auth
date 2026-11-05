from __future__ import annotations

import pytest
from pydantic import SecretStr

from apron_auth.models import ProviderConfig
from apron_auth.providers._host_match import oauth_hosts_match


def _make_config(authorize_url: str, token_url: str) -> ProviderConfig:
    return ProviderConfig(
        client_id="cid",
        client_secret=SecretStr("csecret"),  # pragma: allowlist secret
        authorize_url=authorize_url,
        token_url=token_url,
    )


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

    @pytest.mark.parametrize(
        "authorize_url",
        [
            pytest.param("https://[::1/authorize", id="an authority that cannot be read"),
            pytest.param("https://api.example.com:not-a-port/authorize", id="a port that cannot be read"),
            pytest.param("https:///authorize", id="an authority naming no host"),
        ],
    )
    def test_a_url_no_request_can_be_sent_to_matches_nothing(self, authorize_url: str) -> None:
        """This gate decides which handler may send a credential, so a URL it cannot read matches nothing.

        NOTE: Validation refuses these URLs, so construction without it is the only way one arrives.
        """
        config = ProviderConfig.model_construct(
            client_id="cid",
            client_secret=SecretStr("csecret"),  # pragma: allowlist secret
            authorize_url=authorize_url,
            token_url="https://api.example.com/token",
        )

        assert oauth_hosts_match(config, ("example.com",)) is False

    def test_a_host_written_with_another_dot_matches_the_host_the_client_dials(self) -> None:
        """The client dials the ASCII form, so the suffix list answers for the spelling it reads."""
        config = _make_config(
            authorize_url="https://api.example\u3002com/authorize",
            token_url="https://api.example.com/token",
        )

        assert oauth_hosts_match(config, ("example.com",)) is True

    def test_a_host_in_another_script_matches_no_ascii_suffix(self) -> None:
        """A lookalike reads as its ASCII form, which names a host of its own rather than the suffix."""
        config = _make_config(
            authorize_url="https://\u0430\u0440\u0440\u04cf\u0435.com/authorize",
            token_url="https://\u0430\u0440\u0440\u04cf\u0435.com/token",
        )

        assert oauth_hosts_match(config, ("apple.com",)) is False
