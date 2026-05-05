"""Identity-handler inference for built-in provider presets."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from functools import lru_cache
from typing import cast

from apron_auth import providers as providers_pkg
from apron_auth.models import ProviderConfig
from apron_auth.protocols import IdentityHandler

IdentityResolver = Callable[[ProviderConfig], IdentityHandler | None]


@lru_cache(maxsize=1)
def _identity_resolvers() -> tuple[IdentityResolver, ...]:
    resolvers: list[IdentityResolver] = []
    module_names = sorted(info.name for info in pkgutil.iter_modules(providers_pkg.__path__))
    for module_name in module_names:
        if module_name in {"__init__", "identity"}:
            continue
        module = importlib.import_module(f"{providers_pkg.__name__}.{module_name}")
        resolver = getattr(module, "maybe_identity_handler", None)
        if callable(resolver):
            resolvers.append(cast(IdentityResolver, resolver))
    return tuple(resolvers)


def infer_identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Infer a built-in identity handler from provider modules."""
    for resolver in _identity_resolvers():
        handler = resolver(config)
        if handler is not None:
            return handler
    return None
