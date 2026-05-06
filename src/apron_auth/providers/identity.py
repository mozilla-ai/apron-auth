"""Identity-handler inference for built-in provider presets."""

from __future__ import annotations

import importlib
import pkgutil
from functools import lru_cache

from apron_auth import providers as providers_pkg
from apron_auth.errors import ConfigurationError
from apron_auth.models import ProviderConfig
from apron_auth.protocols import IdentityHandler
from apron_auth.providers._identity_registry import IDENTITY_RESOLVER_ATTR, IdentityResolverRegistration


@lru_cache(maxsize=1)
def _identity_resolver_registrations() -> tuple[IdentityResolverRegistration, ...]:
    registrations: list[IdentityResolverRegistration] = []
    module_names = sorted(info.name for info in pkgutil.iter_modules(providers_pkg.__path__))
    for module_name in module_names:
        # ``providers/`` also contains package plumbing modules; only
        # concrete provider modules participate in identity inference.
        #
        # Conventions:
        # - internal helper modules use a leading underscore
        # - this discovery module is excluded explicitly
        #
        # Guardrails:
        # - registry tests assert these conventions so adding a new public
        #   non-provider module fails in CI with an actionable message.
        if module_name in {"__init__", "identity"} or module_name.startswith("_"):
            continue
        module = importlib.import_module(f"{providers_pkg.__name__}.{module_name}")

        # Guard against future non-provider public modules: provider modules
        # always expose ``preset(...)``.
        if not callable(getattr(module, "preset", None)):
            continue

        registration = getattr(module, IDENTITY_RESOLVER_ATTR, None)
        if registration is None:
            continue
        if not isinstance(registration, IdentityResolverRegistration):
            msg = (
                f"{providers_pkg.__name__}.{module_name}.{IDENTITY_RESOLVER_ATTR} "
                "must be an IdentityResolverRegistration"
            )
            raise TypeError(msg)
        if not callable(registration.resolver):
            msg = f"{providers_pkg.__name__}.{module_name}.{IDENTITY_RESOLVER_ATTR}.resolver must be callable"
            raise TypeError(msg)
        if registration.provider != module_name:
            msg = (
                f"{providers_pkg.__name__}.{module_name}.{IDENTITY_RESOLVER_ATTR}.provider "
                f"must match module name {module_name!r}; got {registration.provider!r}"
            )
            raise ConfigurationError(msg)
        registrations.append(registration)

    seen_providers: set[str] = set()
    for registration in registrations:
        if registration.provider in seen_providers:
            msg = f"Duplicate identity resolver registration for provider {registration.provider!r}"
            raise ConfigurationError(msg)
        seen_providers.add(registration.provider)

    ordered = tuple(sorted(registrations, key=lambda registration: registration.provider))
    return ordered


def infer_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Infer a built-in identity handler from provider modules.

    Returns ``None`` when no provider matches. Raises
    :class:`ConfigurationError` when more than one resolver matches the
    same ``ProviderConfig``.
    """
    matches: list[tuple[str, IdentityHandler]] = []
    for registration in _identity_resolver_registrations():
        handler = registration.resolver(config)
        if handler is not None and not isinstance(handler, IdentityHandler):
            msg = (
                f"{registration.provider} identity resolver returned {type(handler).__name__}, "
                "expected IdentityHandler or None"
            )
            raise TypeError(msg)
        if handler is not None:
            matches.append((registration.provider, handler))

    if not matches:
        return None

    if len(matches) > 1:
        providers = ", ".join(sorted(provider for provider, _ in matches))
        msg = f"Ambiguous identity handler inference for provider config; matched providers: {providers}"
        raise ConfigurationError(msg)

    return matches[0][1]
