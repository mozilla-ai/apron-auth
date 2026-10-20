"""The identity handler of the provider a configuration names."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from apron_auth.errors import ConfigurationError
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from apron_auth.models import ProviderConfig
    from apron_auth.protocols import IdentityHandler


def identity_handler_for(config: ProviderConfig) -> IdentityHandler | None:
    """Build the identity handler of the provider ``config`` names.

    The provider's endpoint hosts are a condition rather than a selector: a config that names a
    provider its endpoints do not belong to is refused, because a handler may derive the endpoint
    it sends the access token to from the config.

    Args:
        config: The provider configuration identity is established under.

    Returns:
        A new handler for the named provider, or ``None`` when the config names no provider or
        allows no handler of its own.

    Raises:
        ConfigurationError: If the config's authorization and token endpoints are not hosts of
            the provider it names.
    """
    provider = config.provider
    if provider is None or not config.allow_identity_inference:
        return None
    if not oauth_hosts_match(config, provider.host_suffixes):
        msg = (
            f"The authorization and token endpoints must both be {provider.display_name} hosts for the "
            f"built-in {provider.display_name} identity handler to apply. Pass an identity handler that "
            f"accepts the configured endpoints, or name no provider for a server that is not "
            f"{provider.display_name}'s."
        )
        raise ConfigurationError(msg)
    # A registry of the ten classes would import every provider module; resolving by name imports one.
    module = import_module(f".{provider.value}", __package__)
    handler: IdentityHandler = getattr(module, provider.identity_handler_class_name)()
    return handler
