"""What a URL states about its transport, read on its own.

Every model rule that accepts or refuses an endpoint reduces to these predicates, so each one is
held to its answer here rather than only through a model that happens to call it.
"""

from __future__ import annotations

import ipaddress

import pytest

from apron_auth._urls import (
    is_loopback_host,
    is_plain_http,
    matches_suffix,
    parse_ip,
    query_parameters,
    url_host,
    uses_allowed_transport,
    uses_secure_transport,
)


class TestIsLoopbackHost:
    """Only what every resolver agrees on, because this decides whether plain HTTP is accepted."""

    @pytest.mark.parametrize(
        "host",
        ["localhost", "localhost.", "127.0.0.1", "127.0.0.1.", "127.0.0.2", "::1"],
    )
    def test_a_canonical_loopback_host_is_loopback(self, host: str) -> None:
        assert is_loopback_host(host) is True

    @pytest.mark.parametrize("host", ["::ffff:127.0.0.1", "::ffff:7f00:1"])
    def test_a_mapped_loopback_address_is_loopback_on_every_interpreter(self, host: str) -> None:
        """The standard library reports the mapping itself as loopback only from some versions."""
        assert is_loopback_host(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            pytest.param("foo.localhost", id="a name under localhost"),
            pytest.param("localhost.evil.example.com", id="localhost as a label"),
            pytest.param("127.1", id="short form"),
            pytest.param("2130706433", id="decimal form"),
            pytest.param("0x7f000001", id="hex form"),
            pytest.param("0177.0.0.1", id="octal form"),
            pytest.param("[::1]", id="brackets"),
            pytest.param("10.0.0.5", id="a private address"),
            pytest.param("", id="no host"),
        ],
    )
    def test_anything_resolvers_disagree_about_is_not_loopback(self, host: str) -> None:
        assert is_loopback_host(host) is False


class TestIsPlainHttp:
    @pytest.mark.parametrize("url", ["http://app.example.com/cb", "http://localhost:8080/cb", "HTTP://app.example.com"])
    def test_http_to_a_named_host_is_plain_http(self, url: str) -> None:
        assert is_plain_http(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://app.example.com/cb", id="https"),
            pytest.param("http:///cb", id="no host"),
            pytest.param("ws://app.example.com/cb", id="another scheme"),
            pytest.param("//app.example.com/cb", id="no scheme"),
            pytest.param("", id="empty"),
            pytest.param("http://[::1/cb", id="unreadable host"),
            pytest.param("http://app.example.com:not-a-port/cb", id="unreadable port"),
        ],
    )
    def test_anything_else_is_not_plain_http(self, url: str) -> None:
        assert is_plain_http(url) is False


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

    def test_a_mixed_case_host_matches(self):
        """DNS names are case-insensitive, and this matcher decides where a credential may be sent."""
        assert matches_suffix("API.Example.COM", ("example.com",)) is True

    def test_a_mixed_case_suffix_matches(self):
        assert matches_suffix("api.example.com", ("Example.COM",)) is True

    def test_no_suffixes_never_matches(self):
        assert matches_suffix("example.com", ()) is False

    def test_substring_after_dot_does_not_match(self):
        assert matches_suffix("attacker.com.example.com.attacker.test", ("example.com",)) is False

    def test_unrelated_host_does_not_match(self):
        assert matches_suffix("other.test", ("example.com",)) is False


class TestParseIp:
    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("127.0.0.1", "127.0.0.1"),
            ("2130706433", "127.0.0.1"),
            ("0x7f000001", "127.0.0.1"),
            ("127.1", "127.0.0.1"),
            ("::1", "::1"),
        ],
    )
    def test_a_legacy_numeric_form_names_the_address_a_resolver_dials(self, host: str, expected: str) -> None:
        assert parse_ip(host) == ipaddress.ip_address(expected)

    @pytest.mark.parametrize(
        "host",
        [
            pytest.param("app.example.com", id="a hostname"),
            pytest.param("", id="empty"),
            pytest.param("localhost\x00.example.com", id="an embedded null"),
        ],
    )
    def test_a_host_that_names_no_address_returns_none(self, host: str) -> None:
        """A host the address parser cannot read is no address, and raising here would escape every rule."""
        assert parse_ip(host) is None


class TestQueryParameters:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param("https://sso.example.com/auth", {}, id="no query"),
            pytest.param("https://sso.example.com/auth?", {}, id="an empty query"),
            pytest.param("https://sso.example.com/auth?prompt=consent", {"prompt": "consent"}, id="one parameter"),
            pytest.param(
                "https://sso.example.com/auth?prompt=consent&access_type=offline",
                {"prompt": "consent", "access_type": "offline"},
                id="two parameters",
            ),
            pytest.param(
                "https://sso.example.com/auth?ui_locales=en&ui_locales=fr",
                {"ui_locales": ["en", "fr"]},
                id="a repeated name keeps every value",
            ),
            pytest.param(
                "https://sso.example.com/auth?scope=openid+email",
                {"scope": "openid email"},
                id="a value is decoded",
            ),
            pytest.param(
                "https://sso.example.com/auth?prompt=",
                {"prompt": ""},
                id="a parameter with an empty value is stated",
            ),
            pytest.param(
                "https://sso.example.com/auth?prompt",
                {"prompt": ""},
                id="a parameter with no value at all is stated",
            ),
        ],
    )
    def test_reads_what_the_query_states(self, url: str, expected: dict[str, str | list[str]]) -> None:
        assert query_parameters(url) == expected

    def test_a_url_the_parser_cannot_read_states_no_parameters(self) -> None:
        """A caller deciding on the parameters must not see this reader's own failure instead."""
        assert query_parameters("https://[::1/auth?state=injected") == {}

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://app.example.com/cb", id="https"),
            pytest.param("http://localhost:8080/cb", id="http to localhost"),
            pytest.param("http://127.0.0.1:8080/cb", id="http to a loopback address"),
        ],
    )
    def test_what_reaches_no_network_or_crosses_it_encrypted_is_protected(self, url: str) -> None:
        assert uses_secure_transport(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("http://app.example.com/cb", id="http to a host on the network"),
            pytest.param("https:///cb", id="https with no host"),
            pytest.param("ws://app.example.com/cb", id="another scheme"),
            pytest.param("javascript:alert(1)", id="a scheme with no transport"),
            pytest.param("com.example.app:/cb", id="private-use scheme"),
            pytest.param("", id="empty"),
            pytest.param("http://[::1/cb", id="unreadable host"),
            pytest.param("https://app.example.com:not-a-port/cb", id="unreadable port"),
            pytest.param("https://app.example.com:99999/cb", id="a port out of range"),
            pytest.param("https://app.exa\tmple.com/cb", id="a control character in the host"),
        ],
    )
    def test_everything_else_states_no_protection(self, url: str) -> None:
        """An HTTP client refuses a URL it cannot read, so this library must not call it protected."""
        assert uses_secure_transport(url) is False


class TestUrlHost:
    """The host a rule reads when it decides where a credential may be sent."""

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            pytest.param("https://slack.com/api/auth.revoke", "slack.com", id="the host it names"),
            pytest.param("https://API.Example.COM/revoke", "api.example.com", id="lowercased, as a DNS name is"),
            pytest.param("https://slack.com:8443/revoke", "slack.com", id="without the port"),
            pytest.param(
                "https://operator:sesame@attacker.example.com/collect",  # pragma: allowlist secret
                "attacker.example.com",
                id="without the userinfo",
            ),
        ],
    )
    def test_reads_the_host_a_request_would_reach(self, url: str, expected: str) -> None:
        assert url_host(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://[::1/revoke", id="unreadable host"),
            pytest.param("https://slack.com:not-a-port/revoke", id="unreadable port"),
            pytest.param("not-a-url", id="no authority at all"),
            pytest.param("https:///revoke", id="an authority with no host"),
            pytest.param("", id="empty"),
        ],
    )
    def test_a_url_no_request_can_be_sent_to_names_no_host(self, url: str) -> None:
        """A rule deciding where a credential may go must read no host rather than part of one."""
        assert url_host(url) == ""


class TestUsesAllowedTransport:
    """One answer for the model rule and the per-call redirect check, so the two cannot diverge."""

    def test_a_waiver_accepts_plain_http_to_a_host_on_the_network(self) -> None:
        assert uses_allowed_transport("http://app.example.com/cb", plain_http_allowed=True) is True

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("ws://app.example.com/cb", id="another scheme"),
            pytest.param("javascript:alert(1)", id="a scheme with no transport"),
            pytest.param("http:///cb", id="plain http with no host"),
            pytest.param("", id="empty"),
        ],
    )
    def test_a_waiver_accepts_nothing_but_plain_http(self, url: str) -> None:
        assert uses_allowed_transport(url, plain_http_allowed=True) is False

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://app.example.com/cb", True),
            ("http://127.0.0.1:8080/cb", True),
            ("http://app.example.com/cb", False),
        ],
    )
    def test_without_a_waiver_it_answers_what_secure_transport_answers(self, url: str, expected: bool) -> None:
        assert uses_allowed_transport(url, plain_http_allowed=False) is expected
