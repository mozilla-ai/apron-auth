"""The identity handler of the provider a configuration names."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from apron_auth.errors import ConfigurationError
from apron_auth.protocols import IdentityHandler
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig

# The package holding one module per provider member, which is this module's own.
_PROVIDER_PACKAGE = __name__.rpartition(".")[0]


def identity_handler_for(config: ProviderConfig) -> IdentityHandler | None:
    """Build the identity handler of the provider ``config`` names.

    The provider's endpoint hosts are a condition rather than a selector.
    A config that names a provider its endpoints do not belong to is refused, because a handler may
    derive the endpoint it sends the access token to from the config.
    NOTE: The named provider's module is imported on the first call that reaches it, so the first
    caller pays for that import.

    Args:
        config: The provider configuration to establish identity under.

    Returns:
        A new handler for the named provider, or ``None`` when the config names no provider or
        allows no handler of its own.

    Raises:
        ConfigurationError: If either the config's authorization or token endpoint is not a host of
            the provider it names.
        TypeError: If the named provider states a class its module does not define, or one that does
            not fetch identity, which is a defect in this library rather than in the config.
    """
    provider = config.provider
    if provider is None or not config.use_builtin_identity_handler:
        return None
    if not oauth_hosts_match(config, provider.host_suffixes):
        msg = (
            f"The authorization and token endpoints must both be {provider.display_name} hosts for its "
            f"built-in identity handler to apply. Pass an identity handler that accepts these endpoints, "
            f"name no provider for a server that is not {provider.display_name}'s, or allow no built-in "
            f"identity handler to take identity from a handler you pass alone."
        )
        raise ConfigurationError(msg)
    # A registry would import every provider module. Resolving by name imports only the named one.
    module = import_module(f"{_PROVIDER_PACKAGE}.{provider.value}")
    handler_class = getattr(module, provider.identity_handler_class_name, None)
    if handler_class is None:
        msg = f"{module.__name__} defines no {provider.identity_handler_class_name}"
        raise TypeError(msg)
    if not (isinstance(handler_class, type) and issubclass(handler_class, IdentityHandler)):
        msg = f"{module.__name__}.{provider.identity_handler_class_name} is not an identity handler"
        raise TypeError(msg)
    return handler_class()
