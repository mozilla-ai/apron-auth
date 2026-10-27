"""The revocation handler of the provider a configuration names, and the request every handler sends through."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module
from typing import TYPE_CHECKING

import httpx

from apron_auth._http_errors import http_failure, status_failure
from apron_auth.errors import ConfigurationError, FailureKind, RevocationError
from apron_auth.protocols import RevocationHandler
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apron_auth.models import ProviderConfig
    from apron_auth.protocols import TransportFactory

# The package holding one module per provider member, which is this module's own.
_PROVIDER_PACKAGE = __name__.rpartition(".")[0]


class HttpMethod(StrEnum):
    """The HTTP methods a provider's revocation endpoint answers."""

    DELETE = "DELETE"
    POST = "POST"


@dataclass(frozen=True, kw_only=True)
class RevocationRequest:
    """What one provider states about its revocation request, beside what the shared send supplies.

    The fields describe one HTTP request and only mean something together, so they travel as one value.

    Attributes:
        url: The endpoint to send to, including any part of the path the provider builds per token.
        label: The provider's display name, which the failure message names.
        auth: HTTP Basic credentials, or ``None`` to present no client authentication.
        data: A form body.
        headers: Request headers.
        json_body: A JSON body.
        method: The method the endpoint answers.
        params: Query parameters.
    """

    url: str
    label: str
    auth: tuple[str, str] | None = None
    data: Mapping[str, str] | None = None
    headers: Mapping[str, str] | None = None
    json_body: Mapping[str, str] | None = None
    method: HttpMethod = HttpMethod.POST
    params: Mapping[str, str] | None = None


class StandardRevocationHandler:
    """RFC 7009 token revocation via POST with token in form body."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        """Configure how revocation requests reach the network.

        Args:
            client: A caller-owned client to send every revocation through;
                when supplied, ``transport_factory`` is unused.
            transport_factory: Factory controlling the outbound connection for
                the revocation URL when no ``client`` is given. The URL is
                server-supplied, so a caller handling untrusted input can pin
                DNS to validated addresses here to prevent SSRF via rebinding.
        """
        self._client = client
        self._transport_factory = transport_factory

    async def revoke(self, token: str, config: ProviderConfig) -> bool:
        """Revoke a token using standard RFC 7009 POST.

        Args:
            token: The token to revoke.
            config: The provider configuration; its ``revocation_url`` and
                client credentials are used for the request.

        Returns:
            ``True`` when the endpoint reports success.

        Raises:
            ConfigurationError: If ``config`` has no revocation URL.
            RevocationError: If the request fails to reach the endpoint.
                The failed request's error is not attached as its cause or context.
        """
        if config.revocation_url is None:
            msg = "the provider configuration carries no revocation endpoint"
            raise ConfigurationError(msg)
        revocation_url = config.revocation_url
        if self._client is not None:
            return await self._send(self._client, token, revocation_url, config)
        transport = self._transport_factory(revocation_url) if self._transport_factory is not None else None
        async with httpx.AsyncClient(transport=transport) as client:
            return await self._send(client, token, revocation_url, config)

    async def _send(
        self,
        client: httpx.AsyncClient,
        token: str,
        revocation_url: str,
        config: ProviderConfig,
    ) -> bool:
        """Send the revocation request and return success status.

        A public client carries no secret, so no HTTP Basic credential is
        attached in that case.

        Args:
            client: The HTTP client to send the request through.
            token: The token to revoke.
            revocation_url: The endpoint to POST the revocation to.
            config: The provider configuration supplying client credentials.

        Returns:
            ``True`` when the endpoint responds with success.

        Raises:
            RevocationError: If the request fails to reach the endpoint, or the endpoint answers an error status.
                Its kind says whether the endpoint may accept the request later.
                The failed request's error is not attached as its cause or context.
        """
        auth = config.basic_auth()
        data = {"token": token}
        if auth is None:
            # RFC 7009 section 5: a public client identifies itself with
            # client_id in the request body, presenting no client authentication.
            data["client_id"] = config.client_id
        try:
            response = await client.post(
                revocation_url,
                data=data,
                # Pass None for a public client, so an injected HTTP client's own auth
                # flow is not applied to the server-supplied revocation URL. The HTTP
                # client accepts None at runtime, and only its type stub omits it.
                auth=auth,  # ty: ignore[invalid-argument-type]
            )
        except httpx.RequestError as exc:
            failure = http_failure(exc)
        else:
            if response.is_success:
                return True
            failure = status_failure(response.status_code)
        # NOTE: The caught error holds the request, which carries the token, so this error must not reference it.
        # This raise stays outside the except block, where Python would set __context__ to the caught error.
        raise RevocationError(f"Failed to revoke token: {failure.description}", kind=failure.kind)


def revocation_endpoint(config: ProviderConfig) -> str:
    """Return the revocation endpoint ``config`` declares.

    Args:
        config: The provider configuration to revoke against.

    Returns:
        The endpoint.

    Raises:
        ConfigurationError: If the configuration declares none.
    """
    if config.revocation_url is None:
        msg = "the provider configuration carries no revocation endpoint"
        raise ConfigurationError(msg)
    return config.revocation_url


async def send_revocation(
    request: RevocationRequest,
    *,
    transport_factory: TransportFactory | None = None,
) -> httpx.Response:
    """Send one revocation request and return its response, whatever status it carries.

    A provider reads success its own way, so this states no success rule and leaves the response to its caller.

    Args:
        request: What the provider states about the request.
        transport_factory: Controls the outbound connection. The URL is server-supplied, so a caller
            handling untrusted input can pin DNS to validated addresses here to prevent SSRF via rebinding.

    Returns:
        The endpoint's response.

    Raises:
        RevocationError: If the URL is invalid, or the request cannot be sent or fails to arrive.
            Its kind says whether the same request may pass later.
            The caught error is not attached as its cause or context.
    """
    transport = transport_factory(request.url) if transport_factory is not None else None
    try:
        async with httpx.AsyncClient(transport=transport) as client:
            return await client.request(
                request.method,
                request.url,
                auth=request.auth,
                data=request.data,
                headers=request.headers,
                json=request.json_body,
                params=request.params,
            )
    # NOTE: httpx.InvalidURL is not an httpx.HTTPError, so it needs its own clause.
    except httpx.InvalidURL:
        failure_message, kind = f"Failed to revoke {request.label} token: invalid URL", FailureKind.REFUSED
    except httpx.HTTPError as exc:
        failure = http_failure(exc)
        failure_message, kind = f"Failed to revoke {request.label} token: {failure.description}", failure.kind
    except Exception:
        # A token that is not ASCII cannot go in a header, and the encoding error repeats it.
        failure_message, kind = f"Failed to revoke {request.label} token: request failed", FailureKind.UNEXPECTED
    # NOTE: The caught error holds the token-bearing request, so this error must not chain it.
    # This raise stays outside the except blocks, where Python would set __context__ to the caught error.
    raise RevocationError(failure_message, kind=kind)


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
