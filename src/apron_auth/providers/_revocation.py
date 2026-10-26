"""The revocation handler of the provider a configuration names."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from apron_auth.protocols import RevocationHandler, StandardRevocationHandler

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig

# The package holding one module per provider member, which is this module's own.
_PROVIDER_PACKAGE = __name__.rpartition(".")[0]


def revocation_handler_for(config: ProviderConfig) -> RevocationHandler | None:
    """Build the revocation handler of the provider ``config`` names.

    A provider that needs nothing of its own takes RFC 7009 revocation, and one that needs more
    names a class of its own on its member.
    NOTE: The named provider's module is imported on the first call that reaches it, so the first
    caller pays for that import.

    Args:
        config: The provider configuration to revoke against.

    Returns:
        A new handler for the named provider, or ``None`` when the config names no provider or
        declares no revocation endpoint.

    Raises:
        TypeError: If the named provider states a class its module does not define, or one that
            does not revoke, which is a defect in this library rather than in the config.
    """
    provider = config.provider
    if provider is None or config.revocation_url is None:
        return None
    class_name = provider.revocation_handler_class_name
    if class_name is None:
        return StandardRevocationHandler()
    # A registry would import every provider module. Resolving by name imports only the named one.
    module = import_module(f"{_PROVIDER_PACKAGE}.{provider.value}")
    handler_class = getattr(module, class_name, None)
    if handler_class is None:
        msg = f"{module.__name__} defines no {class_name}"
        raise TypeError(msg)
    if not (isinstance(handler_class, type) and issubclass(handler_class, RevocationHandler)):
        msg = f"{module.__name__}.{class_name} is not a revocation handler"
        raise TypeError(msg)
    return handler_class()
