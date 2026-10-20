"""The identity handler of the provider a configuration names."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from apron_auth.errors import ConfigurationError
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig
    from apron_auth.protocols import IdentityHandler

# The package that holds one module per provider member.
_PROVIDER_PACKAGE = "apron_auth.providers"


def identity_handler(config: ProviderConfig) -> IdentityHandler | None:
    """Build the identity handler of the provider ``config`` names.

    The provider's endpoint hosts are a condition rather than a selector: a config that names a
    provider its endpoints do not belong to is refused, because a handler may derive the endpoint
    it sends the access token to from the config.

    Args:
        config: The provider configuration identity is established under.

    Returns:
        A new handler for the named provider, or ``None`` when the config names no provider.

    Raises:
        ConfigurationError: If the config's authorization and token endpoints are not hosts of
            the provider it names.
    """
    provider = config.provider
    if provider is None:
        return None
    if not oauth_hosts_match(config, provider.host_suffixes):
        msg = (
            f"The configured authorization and token endpoints are not {provider.display_name}'s, "
            f"so the built-in {provider.display_name} identity handler does not apply. "
            f"Pass an identity handler for a {provider.display_name} deployment on other hosts."
        )
        raise ConfigurationError(msg)
    # Only the named provider's module is imported, so naming one provider loads no other.
    module = import_module(f"{_PROVIDER_PACKAGE}.{provider.value}")
    handler: IdentityHandler = getattr(module, provider.identity_handler_class_name)()
    return handler
