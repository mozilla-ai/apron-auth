from __future__ import annotations

import importlib
import pkgutil
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from apron_auth import providers as providers_pkg
from apron_auth.errors import ConfigurationError
from apron_auth.models import ProviderConfig
from apron_auth.providers._identity_registry import IdentityResolverRegistration
from apron_auth.providers.identity import _identity_resolver_registrations, infer_identity_handler


def _make_config() -> ProviderConfig:
    return ProviderConfig(
        client_id="test-client",
        client_secret=SecretStr("test-secret"),
        authorize_url="https://provider.example.com/authorize",
        token_url="https://provider.example.com/token",
    )


@pytest.fixture(autouse=True)
def _clear_identity_registry_cache():
    _identity_resolver_registrations.cache_clear()
    yield
    _identity_resolver_registrations.cache_clear()


class TestInferIdentityHandler:
    def test_multiple_matches_raise_configuration_error(self, monkeypatch):
        class HandlerA:
            async def fetch_identity(self, access_token: str, config: ProviderConfig):
                del access_token, config
                return None

        class HandlerB:
            async def fetch_identity(self, access_token: str, config: ProviderConfig):
                del access_token, config
                return None

        def resolver_a(config: ProviderConfig):
            del config
            return HandlerA()

        def resolver_b(config: ProviderConfig):
            del config
            return HandlerB()

        registrations = (
            IdentityResolverRegistration(provider="a", resolver=resolver_a),
            IdentityResolverRegistration(provider="b", resolver=resolver_b),
        )

        _identity_resolver_registrations.cache_clear()
        monkeypatch.setattr(
            "apron_auth.providers.identity._identity_resolver_registrations",
            lambda: registrations,
        )

        with pytest.raises(ConfigurationError, match="Ambiguous identity handler inference"):
            infer_identity_handler(_make_config())

    def test_no_matches_returns_none(self, monkeypatch):
        _identity_resolver_registrations.cache_clear()
        monkeypatch.setattr(
            "apron_auth.providers.identity._identity_resolver_registrations",
            lambda: (),
        )

        assert infer_identity_handler(_make_config()) is None

    def test_single_match_returns_handler(self, monkeypatch):
        class Handler:
            async def fetch_identity(self, access_token: str, config: ProviderConfig):
                del access_token, config
                return None

        def resolver(config: ProviderConfig):
            del config
            return Handler()

        registrations = (IdentityResolverRegistration(provider="only", resolver=resolver),)

        _identity_resolver_registrations.cache_clear()
        monkeypatch.setattr(
            "apron_auth.providers.identity._identity_resolver_registrations",
            lambda: registrations,
        )

        assert isinstance(infer_identity_handler(_make_config()), Handler)

    def test_non_handler_match_raises_type_error(self, monkeypatch):
        def bad_resolver(config: ProviderConfig):
            del config
            return object()

        registrations = (IdentityResolverRegistration(provider="bad", resolver=bad_resolver),)

        monkeypatch.setattr(
            "apron_auth.providers.identity._identity_resolver_registrations",
            lambda: registrations,
        )

        with pytest.raises(TypeError, match="expected IdentityHandler or None"):
            infer_identity_handler(_make_config())


class TestIdentityResolverRegistrations:
    def test_public_provider_modules_expose_preset(self):
        module_names = sorted(info.name for info in pkgutil.iter_modules(providers_pkg.__path__))
        missing_preset: list[str] = []

        for module_name in module_names:
            if module_name in {"__init__", "identity"} or module_name.startswith("_"):
                continue
            module = importlib.import_module(f"{providers_pkg.__name__}.{module_name}")
            if not callable(getattr(module, "preset", None)):
                missing_preset.append(module_name)

        assert not missing_preset, (
            "Public modules under apron_auth.providers must be concrete provider modules "
            "and expose preset(...). If this is a helper, rename it with a leading underscore. "
            f"Missing preset: {', '.join(missing_preset)}"
        )

    def test_private_modules_are_not_treated_as_provider_modules(self):
        _identity_resolver_registrations.cache_clear()
        registrations = _identity_resolver_registrations()
        provider_names = {registration.provider for registration in registrations}

        assert "_host_match" not in provider_names
        assert "_identity_registry" not in provider_names

    def test_registration_order_is_deterministic(self):
        _identity_resolver_registrations.cache_clear()
        registrations = _identity_resolver_registrations()
        provider_names = [registration.provider for registration in registrations]

        assert provider_names == sorted(provider_names)

    def test_expected_identity_providers_are_registered(self):
        _identity_resolver_registrations.cache_clear()
        registrations = _identity_resolver_registrations()
        provider_names = {registration.provider for registration in registrations}

        assert provider_names == {
            "atlassian",
            "github",
            "google",
            "hubspot",
            "linear",
            "microsoft",
            "notion",
            "salesforce",
            "typeform",
        }

    def test_expected_identity_provider_modules_expose_typed_registration(self):
        expected_identity_providers = {
            "atlassian",
            "github",
            "google",
            "hubspot",
            "linear",
            "microsoft",
            "notion",
            "salesforce",
            "typeform",
        }

        for provider in expected_identity_providers:
            module = importlib.import_module(f"apron_auth.providers.{provider}")
            registration = getattr(module, "IDENTITY_RESOLVER", None)

            assert isinstance(registration, IdentityResolverRegistration)
            assert registration.provider == provider
            assert callable(registration.resolver)
            assert registration.resolver is module.maybe_identity_handler

    def test_provider_name_must_match_module_name(self, monkeypatch):
        def resolver(config: ProviderConfig):
            del config
            return None

        fake_module = SimpleNamespace(
            preset=lambda *args, **kwargs: None,
            IDENTITY_RESOLVER=IdentityResolverRegistration(provider="github", resolver=resolver),
        )

        monkeypatch.setattr(
            "apron_auth.providers.identity.pkgutil.iter_modules",
            lambda _: [SimpleNamespace(name="google")],
        )
        monkeypatch.setattr(
            "apron_auth.providers.identity.importlib.import_module",
            lambda _: fake_module,
        )

        with pytest.raises(ConfigurationError, match="must match module name"):
            _identity_resolver_registrations()

    def test_duplicate_provider_registration_raises_configuration_error(self, monkeypatch):
        def resolver(config: ProviderConfig):
            del config
            return None

        module_a = SimpleNamespace(
            preset=lambda *args, **kwargs: None,
            IDENTITY_RESOLVER=IdentityResolverRegistration(provider="a", resolver=resolver),
        )
        module_b = SimpleNamespace(
            preset=lambda *args, **kwargs: None,
            IDENTITY_RESOLVER=IdentityResolverRegistration(provider="a", resolver=resolver),
        )
        modules = iter([module_a, module_b])

        monkeypatch.setattr(
            "apron_auth.providers.identity.pkgutil.iter_modules",
            lambda _: [SimpleNamespace(name="a"), SimpleNamespace(name="a")],
        )
        monkeypatch.setattr(
            "apron_auth.providers.identity.importlib.import_module",
            lambda _: next(modules),
        )

        with pytest.raises(ConfigurationError, match="Duplicate identity resolver registration"):
            _identity_resolver_registrations()

    def test_public_modules_without_preset_are_ignored(self, monkeypatch):
        fake_helper_module = SimpleNamespace(
            helper=lambda: None,
        )

        monkeypatch.setattr(
            "apron_auth.providers.identity.pkgutil.iter_modules",
            lambda _: [SimpleNamespace(name="public_helper")],
        )
        monkeypatch.setattr(
            "apron_auth.providers.identity.importlib.import_module",
            lambda _: fake_helper_module,
        )

        assert _identity_resolver_registrations() == ()
