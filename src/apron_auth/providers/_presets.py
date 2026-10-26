"""The data one provider's preset declares, and the configuration it builds from a caller's values."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import SecretStr

from apron_auth.errors import ConfigurationError
from apron_auth.models import ProviderConfig, TokenEndpointAuthMethod

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from apron_auth.models import Provider, ScopeMetadata


def scope_sequence(scopes: Sequence[str] | None, field: str) -> list[str]:
    """Return ``scopes`` as a list, refusing a bare string.

    A string is itself a sequence of characters, so taking one would request each letter as a scope.

    Args:
        scopes: The scopes a caller stated, or ``None`` where the parameter is optional.
        field: The parameter's name, for the refusal to name.

    Returns:
        The scopes as a list, empty where the caller stated none.

    Raises:
        ConfigurationError: If ``scopes`` is a string.
    """
    if isinstance(scopes, str):
        msg = f"{field} must be a sequence of scope strings, not one string"
        raise ConfigurationError(msg)
    return list(scopes or [])


@dataclass(frozen=True, kw_only=True)
class Preset:
    """What one provider's preset states, beside the values its caller passes.

    The endpoints come first in the order an authorization flow uses them, and the rest are A-Z.

    Attributes:
        provider: The provider member this configuration names.
        authorize_url: The provider's authorization endpoint.
        token_url: The provider's token endpoint.
        revocation_url: The provider's revocation endpoint, or ``None`` where it publishes none.
        base_scopes: Scopes this preset requests beside the caller's. Empty where it adds none,
            and the caller's scopes then reach the configuration as they were given.
        default_extra_params: Authorization-request parameters this preset sends unless the caller
            states the same key.
        implicit_scopes: Scopes a provider grants without naming them in a granted scope string.
        issuer: The issuer an ID token from this flow must name, or ``None`` where the flow returns none.
        required_scope_families: Scope families a consumer must keep at least one member of.
        scope_metadata: Consent-UI metadata for the scopes this preset injects.
        token_endpoint_auth_method: How the client authenticates at the token endpoint.
        use_pkce: Whether the flow sends a PKCE challenge.
    """

    provider: Provider
    authorize_url: str
    token_url: str
    revocation_url: str | None = None
    base_scopes: Sequence[str] = ()
    default_extra_params: Mapping[str, str] = field(default_factory=dict)
    implicit_scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)
    issuer: str | None = None
    required_scope_families: Sequence[Sequence[str]] = ()
    scope_metadata: Sequence[ScopeMetadata] = ()
    token_endpoint_auth_method: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_POST
    use_pkce: bool = True

    def config(
        self,
        client_id: str,
        client_secret: str,
        *,
        scopes: Sequence[str],
        redirect_uri: str | None = None,
        extra_params: Mapping[str, str] | None = None,
    ) -> ProviderConfig:
        """Build the provider configuration this preset states, from the values a caller passes.

        Args:
            client_id: The OAuth client identifier.
            client_secret: The OAuth client secret.
            scopes: Scopes to request beside the ones this preset states.
            redirect_uri: The redirect URI for the authorization flow.
            extra_params: Authorization-request parameters, which take precedence over the ones
                this preset states under the same key.

        Returns:
            The configuration, naming this preset's provider.

        Raises:
            ConfigurationError: If the values do not describe a configuration this library accepts.
        """
        return ProviderConfig(
            provider=self.provider,
            client_id=client_id,
            client_secret=SecretStr(client_secret),
            authorize_url=self.authorize_url,
            token_url=self.token_url,
            revocation_url=self.revocation_url,
            redirect_uri=redirect_uri,
            scopes=self._requested_scopes(scope_sequence(scopes, "scopes")),
            use_pkce=self.use_pkce,
            token_endpoint_auth_method=self.token_endpoint_auth_method,
            extra_params={**self.default_extra_params, **(extra_params or {})},
            scope_metadata=list(self.scope_metadata),
            implicit_scopes=dict(self.implicit_scopes),
            issuer=self.issuer,
            required_scope_families=[list(family) for family in self.required_scope_families],
        )

    def _requested_scopes(self, scopes: Sequence[str]) -> list[str]:
        """Return the scopes the configuration requests, merged with this preset's own.

        Args:
            scopes: The scopes the caller asked for.

        Returns:
            The caller's scopes as given where this preset states none of its own, and the two sets
            merged and ordered A-Z where it does.
        """
        if not self.base_scopes:
            return list(scopes)
        return sorted(set(self.base_scopes) | set(scopes))
