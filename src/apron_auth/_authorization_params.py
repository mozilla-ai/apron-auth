"""The authorization-request parameters a provider configuration sends."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from apron_auth.models import RESERVED_AUTHORIZATION_PARAMS
from apron_auth.scopes import join_scopes, scope_words

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apron_auth.models import ProviderConfig


def authorization_query(config: ProviderConfig, params: dict[str, str]) -> dict[str, str | list[str]]:
    """Return the query of an authorization URL that sends ``params`` for ``config``.

    The authorization URL's own query is overridden by ``params``, then by the extra parameters,
    then by the resource. A reserved parameter is dropped from the URL's own query and from the
    extra parameters, so only the request's own client sets it.

    Args:
        config: The provider configuration the request is built from.
        params: The request parameters the client sets.

    Returns:
        The query, with each parameter's value or values.
    """
    # A reserved parameter binds the request to one client, or replaces the request as a whole,
    # so the config must not set one, even when it was built without validation.
    query: dict[str, str | list[str]] = {
        name: values[0] if len(values) == 1 else values
        for name, values in parse_qs(urlparse(config.authorize_url).query).items()
        if name not in RESERVED_AUTHORIZATION_PARAMS
    }
    query.update(params)
    query.update(
        {name: value for name, value in config.extra_params.items() if name not in RESERVED_AUTHORIZATION_PARAMS}
    )
    # The resource indicator (RFC 8707) is authoritative for audience binding,
    # so extra_params must not be able to suppress or redirect it.
    if config.resource is not None:
        query["resource"] = config.resource
    return query


def scope_param(config: ProviderConfig) -> dict[str, str]:
    """Return the ``scope`` request parameter for a configuration's scopes.

    Args:
        config: The provider configuration to read.

    Returns:
        The parameter, or no parameter when the configuration carries no scopes.
    """
    if not config.scopes:
        return {}
    return {"scope": join_scopes(config.scopes, config.scope_separator)}


def sent_scope_words(query: Mapping[str, str | list[str]], parameter: str, separator: str) -> set[str]:
    """Return the scope words an authorization query carries in one of its scope parameters.

    Args:
        query: The query of an authorization URL.
        parameter: The name of the scope parameter to read.
        separator: A further delimiter the provider joins its scopes with.

    Returns:
        The words, or no words when the query carries that parameter with no value.
    """
    value = query.get(parameter)
    values = [value] if isinstance(value, str) else value or []
    return scope_words(values, separator)
