"""The revocation handler of the provider a configuration names."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from apron_auth.errors import ConfigurationError
from apron_auth.protocols import RevocationHandler, StandardRevocationHandler
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig
    from apron_auth.protocols import TransportFactory

# The package holding one module per provider member, which is this module's own.
_PROVIDER_PACKAGE = __name__.rpartition(".")[0]


def revocation_handler_for(
    config: ProviderConfig,
    *,
    transport_factory: TransportFactory | None = None,
) -> RevocationHandler | None:
    """Build the revocation handler of the provider ``config`` names.

    A provider that needs nothing of its own takes RFC 7009 revocation, and one that needs more
    names a class of its own on its member. Its endpoint hosts are a condition on that class alone,
    because such a class may state the token where RFC 7009 does not, such as in the request line.
    NOTE: The named provider's module is imported on the first call that reaches it, so the first
    caller pays for that import.

    Args:
        config: The provider configuration to revoke against.
        transport_factory: Controls the outbound connection for RFC 7009 revocation, where a caller
            handling untrusted input can pin DNS to validated addresses. A provider that names a
            class of its own takes no factory, because none of those classes accepts one.

    Returns:
        A new handler for the named provider, or ``None`` when the config names no provider or
        declares no revocation endpoint.

    Raises:
        ConfigurationError: If the named provider states a class of its own and either of the
            config's OAuth endpoints is not one of that provider's hosts.
        TypeError: If the named provider states a class its module does not define, or one that
            does not revoke, which is a defect in this library rather than in the config.
    """
    provider = config.provider
    if provider is None or config.revocation_url is None:
        return None
    class_name = provider.revocation_handler_class_name
    if class_name is None:
        return StandardRevocationHandler(transport_factory=transport_factory)
    if not oauth_hosts_match(config, provider.host_suffixes):
        msg = (
            f"The authorization and token endpoints must both be {provider.display_name} hosts for its "
            f"own revocation handler to apply, because that handler may state the token where RFC 7009 "
            f"does not. Pass a revocation handler that accepts these endpoints, or name no provider for "
            f"a server that is not {provider.display_name}'s."
        )
        raise ConfigurationError(msg)
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
