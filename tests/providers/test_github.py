from __future__ import annotations

import json

import httpx
import pytest
from pytest_httpx import HTTPXMock

from apron_auth.errors import FailureKind, RevocationError
from apron_auth.models import IdentityMaterial, ProviderConfig, SecretToken
from apron_auth.protocols import RevocationHandler
from apron_auth.providers import revocation_handler_for
from apron_auth.providers.github import GitHubRevocationHandler


class TestGitHubPreset:
    def test_returns_a_configuration_its_provider_handler_resolves_from(self) -> None:
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert isinstance(config, ProviderConfig)
        assert isinstance(revocation_handler_for(config), RevocationHandler)

    def test_config_has_correct_endpoints(self) -> None:
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert config.authorize_url == "https://github.com/login/oauth/authorize"
        assert config.token_url == "https://github.com/login/oauth/access_token"
        assert config.revocation_url == "https://api.github.com/applications/ghid/grant"

    def test_base_scopes_merged_with_caller_scopes(self) -> None:
        from apron_auth.providers.github import BASE_SCOPES, preset

        config = preset(
            client_id="ghid",
            client_secret="ghsecret",  # pragma: allowlist secret
            scopes=["repo"],
        )
        for scope in BASE_SCOPES:
            assert scope in config.scopes
        assert "repo" in config.scopes

    def test_duplicate_scopes_deduplicated(self) -> None:
        from apron_auth.providers.github import preset

        config = preset(
            client_id="ghid",
            client_secret="ghsecret",  # pragma: allowlist secret
            scopes=["read:user", "repo"],
        )
        assert config.scopes.count("read:user") == 1

    def test_scope_metadata_covers_base_scopes(self) -> None:
        from apron_auth.providers.github import BASE_SCOPES, preset

        config = preset(
            client_id="ghid",
            client_secret="ghsecret",  # pragma: allowlist secret
            scopes=["repo"],
        )
        metadata_scopes = {meta.scope for meta in config.scope_metadata}
        assert metadata_scopes == set(BASE_SCOPES)
        assert all(meta.required for meta in config.scope_metadata)


class TestGitHubImplicitScopes:
    def test_preset_populates_implicit_scopes(self) -> None:
        from apron_auth.providers.github import IMPLICIT_SCOPES, preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        assert config.implicit_scopes == IMPLICIT_SCOPES

    @pytest.mark.parametrize(
        ("granted", "expected"),
        [
            # repo umbrella -> its five documented sub-scopes.
            (
                {"repo"},
                {"repo", "public_repo", "repo:invite", "repo:status", "repo_deployment", "security_events"},
            ),
            # user umbrella -> read:user plus email/follow.
            ({"user"}, {"user", "read:user", "user:email", "user:follow"}),
            # admin >= write >= read ladders resolve transitively.
            ({"admin:org"}, {"admin:org", "write:org", "read:org"}),
            ({"admin:public_key"}, {"admin:public_key", "write:public_key", "read:public_key"}),
            ({"admin:gpg_key"}, {"admin:gpg_key", "write:gpg_key", "read:gpg_key"}),
            ({"admin:repo_hook"}, {"admin:repo_hook", "write:repo_hook", "read:repo_hook"}),
            # project read/write implies read-only.
            ({"project"}, {"project", "read:project"}),
            # admin:enterprise -> its three documented children.
            (
                {"admin:enterprise"},
                {"admin:enterprise", "manage_billing:enterprise", "manage_runners:enterprise", "read:enterprise"},
            ),
        ],
    )
    def test_documented_implications_resolve(self, granted: set[str], expected: set[str]) -> None:
        from apron_auth.providers.github import preset

        # Requested scopes don't affect implicit_scopes; it is fixed per provider.
        config = preset(client_id="ghid", client_secret="ghsecret", scopes=[])
        assert config.resolve_implicit_scopes(granted) == expected


_GITHUB_USER_URL = "https://api.github.com/user"
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


class TestGitHubIdentityHandler:
    async def test_fetch_identity_populates_provider(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=_GITHUB_USER_URL,
            json={"id": 12345, "login": "octocat", "name": "The Octocat", "avatar_url": "https://example.com/a"},
        )
        httpx_mock.add_response(
            url=_GITHUB_EMAILS_URL,
            json=[{"email": "octocat@example.com", "primary": True, "verified": True}],
        )
        from apron_auth.providers.github import GitHubIdentityHandler, preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        handler = GitHubIdentityHandler()

        identity = await handler.fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.provider == "github"
        assert identity.subject == "12345"
        assert identity.email == "octocat@example.com"
        assert identity.email_verified is True

    @pytest.mark.parametrize(
        "stated",
        [
            pytest.param({"address": "octocat@example.com"}, id="an object"),
            pytest.param(["octocat@example.com"], id="a list"),
            pytest.param(7, id="a number"),
            pytest.param("", id="nothing at all"),
        ],
    )
    async def test_an_address_of_another_type_is_passed_over(self, httpx_mock: HTTPXMock, stated: object) -> None:
        """Rendering one as text would report what the response states about it, as a verified address."""
        httpx_mock.add_response(url=_GITHUB_USER_URL, json={"id": 1, "login": "octocat", "email": None})
        httpx_mock.add_response(
            url=_GITHUB_EMAILS_URL,
            json=[{"email": stated, "primary": True, "verified": True}],
        )
        from apron_auth.providers.github import GitHubIdentityHandler, preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])

        identity = await GitHubIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email is None
        assert identity.email_verified is None

    @pytest.mark.parametrize(
        "stated",
        [
            pytest.param("false", id="the string false"),
            pytest.param(1, id="the number one"),
        ],
    )
    async def test_a_primary_flag_of_another_type_selects_no_address(
        self, httpx_mock: HTTPXMock, stated: object
    ) -> None:
        """A flag stating the address is not preferred would otherwise select it, because any text is truthy."""
        httpx_mock.add_response(url=_GITHUB_USER_URL, json={"id": 1, "login": "octocat", "email": None})
        httpx_mock.add_response(
            url=_GITHUB_EMAILS_URL,
            json=[
                {"email": "other@example.com", "verified": True},
                {"email": "claims-primary@example.com", "primary": stated, "verified": True},
            ],
        )
        from apron_auth.providers.github import GitHubIdentityHandler, preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])

        identity = await GitHubIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email == "other@example.com"
        assert identity.email_verified is True

    async def test_a_primary_flag_stated_as_a_boolean_selects_its_address(self, httpx_mock: HTTPXMock) -> None:
        """The preference is honored where the provider states it in the type it documents."""
        httpx_mock.add_response(url=_GITHUB_USER_URL, json={"id": 1, "login": "octocat", "email": None})
        httpx_mock.add_response(
            url=_GITHUB_EMAILS_URL,
            json=[
                {"email": "other@example.com", "verified": True},
                {"email": "preferred@example.com", "primary": True, "verified": True},
            ],
        )
        from apron_auth.providers.github import GitHubIdentityHandler, preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])

        identity = await GitHubIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email == "preferred@example.com"
        assert identity.email_verified is True

    @pytest.mark.parametrize(
        "stated",
        [
            pytest.param("false", id="the string false"),
            pytest.param("true", id="the string true"),
            pytest.param(1, id="the number one"),
        ],
    )
    async def test_a_verified_flag_of_another_type_selects_no_address(
        self, httpx_mock: HTTPXMock, stated: object
    ) -> None:
        """A coerced flag reports an address as verified on a value that asserts nothing about it."""
        httpx_mock.add_response(url=_GITHUB_USER_URL, json={"id": 1, "login": "octocat", "email": None})
        httpx_mock.add_response(
            url=_GITHUB_EMAILS_URL,
            json=[{"email": "octocat@example.com", "primary": True, "verified": stated}],
        )
        from apron_auth.providers.github import GitHubIdentityHandler, preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])

        identity = await GitHubIdentityHandler().fetch_identity(IdentityMaterial(access_token="access-abc"), config)

        assert identity.email is None
        assert identity.email_verified is None


class TestGitHubRevocationHandler:
    async def test_revokes_via_delete_with_basic_auth(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)
        assert result is True
        request = httpx_mock.get_request()
        assert request.method == "DELETE"
        assert request.headers.get("authorization", "").startswith("Basic ")

    async def test_sends_github_api_headers(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)
        request = httpx_mock.get_request()
        assert request.headers.get("accept") == "application/vnd.github+json"
        assert request.headers.get("x-github-api-version") == "2022-11-28"

    async def test_sends_access_token_in_body(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=204)
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)
        request = httpx_mock.get_request()
        payload = json.loads(request.content)
        assert payload == {"access_token": "access-abc"}

    async def test_not_found_is_idempotent_success(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=404)
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)
        assert result is True

    async def test_validation_failure_returns_false(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=422)
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        result = await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)
        assert result is False

    async def test_a_status_github_does_not_state_is_refused(self, httpx_mock: HTTPXMock) -> None:
        """A 422 is GitHub refusing; every other unexpected status leaves the outcome unknown."""
        httpx_mock.add_response(status_code=500)
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        with pytest.raises(RevocationError) as refusal:
            await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)

        assert refusal.value.kind is FailureKind.SERVER_ERROR

    async def test_network_error_raises_revocation_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        from apron_auth.providers.github import preset

        config = preset(client_id="ghid", client_secret="ghsecret", scopes=["repo"])
        with pytest.raises(RevocationError, match="^Failed to revoke GitHub token: network error$") as exc_info:
            await GitHubRevocationHandler().revoke(SecretToken("access-abc"), config)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
