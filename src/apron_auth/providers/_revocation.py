"""The revocation handler of the provider a configuration names, and the request every handler sends through."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module
from typing import TYPE_CHECKING, NoReturn, assert_never

import httpx
from pydantic import SecretStr

from apron_auth._http_errors import http_failure, response_failure
from apron_auth._timeouts import httpx_timeout, within_request_limit
from apron_auth._urls import AuthorityCredential, authority_credential, url_host, uses_allowed_transport
from apron_auth.errors import ConfigurationError, FailureKind, RevocationError
from apron_auth.models import SecretToken, UrlField
from apron_auth.protocols import RevocationHandler
from apron_auth.providers._host_match import oauth_hosts_match

if TYPE_CHECKING:
    from collections.abc import Mapping

    from apron_auth.models import ProviderConfig
    from apron_auth.protocols import TransportFactory

# The package holding one module per provider member, which is this module's own.
_PROVIDER_PACKAGE = __name__.rpartition(".")[0]

# The statuses an RFC 7009 endpoint states a revocation it completed with. Section 2.2 documents 200,
# and 204 states the same outcome carrying no body. Any other success states the work is not done.
_REVOKED_STATUSES = (200, 204)


class HttpMethod(StrEnum):
    """The HTTP methods a provider's revocation endpoint answers."""

    DELETE = "DELETE"
    POST = "POST"


@dataclass(frozen=True, kw_only=True, repr=False)
class RevocationRequest:
    """What one provider states about its revocation request, beside what the shared send supplies.

    The fields describe one HTTP request and only mean something together, so they travel as one value.

    Attributes:
        url: The endpoint to send to, including any part of the path the provider builds per token.
        label: The provider's display name, which the failure message names, or ``None`` where the
            configuration names no provider and the message names none either.
        endpoint: The URL the outbound connection is chosen for, where a provider builds ``url`` per
            token and that URL therefore carries the token. ``None`` means ``url`` carries no token
            and serves for both.
        auth: HTTP Basic credentials, or ``None`` to present no client authentication.
        data: A form body.
        headers: Request headers.
        json_body: A JSON body.
        method: The method the endpoint answers.
        params: Query parameters.
    """

    url: str
    label: str | None = None
    endpoint: str | None = None
    auth: tuple[str, SecretStr] | None = None
    data: Mapping[str, str] | None = None
    headers: Mapping[str, str] | None = None
    json_body: Mapping[str, str] | None = None
    method: HttpMethod = HttpMethod.POST
    params: Mapping[str, str] | None = None

    def __repr__(self) -> str:
        """Return what the request is for, stating nothing it carries.

        An error reporter records the repr of every local of every frame a traceback holds, and a
        provider may state a credential in any part of its request, including the request line.
        What appears is therefore named here rather than left out here, so a part added later is
        absent until it is named.

        Returns:
            The method, the provider's label, and the host the request would reach.
        """
        return f"{type(self).__name__}(method={self.method}, label={self.label!r}, host={url_host(self.url)!r})"


class StandardRevocationHandler:
    """RFC 7009 token revocation: a POST whose form body carries the token.

    RFC 7009 section 2.2 documents one status for a revocation the endpoint completed, which it
    answers for an invalid token as well, so a body states no condition this reads.
    """

    def __init__(self, *, transport_factory: TransportFactory | None = None) -> None:
        """Configure how revocation requests reach the network.

        Args:
            transport_factory: Controls the outbound connection for the revocation URL. The URL is
                server-supplied, so a caller handling untrusted input can pin DNS to validated
                addresses here to prevent SSRF via rebinding.
                NOTE: The transport it returns is closed when the request completes, so a factory
                must not return one it intends to reuse.
        """
        self._transport_factory = transport_factory

    async def revoke(self, token: SecretToken, config: ProviderConfig) -> bool:
        """Revoke a token at the configuration's RFC 7009 endpoint.

        Args:
            token: The token to revoke.
            config: The provider configuration, whose revocation endpoint and client credentials
                the request carries.

        Returns:
            ``True`` when the endpoint states the revocation complete.

        Raises:
            ConfigurationError: If the configuration declares no revocation endpoint, or declares one
                it does not permit sending a token to.
            RevocationError: If the request cannot be sent or fails to arrive, or the endpoint
                answers an error status.
                The failed request's error is not attached as its cause or context.
        """
        auth = config.basic_auth()
        provider = config.provider
        request = RevocationRequest(
            url=revocation_endpoint(config),
            label=None if provider is None else provider.display_name,
            auth=auth,
            data={"token": token.get_secret_value()}
            if auth is not None
            # RFC 7009 section 5: a public client identifies itself with client_id in the request
            # body, presenting no client authentication.
            else {"token": token.get_secret_value(), "client_id": config.client_id},
        )
        response = await send_revocation(request, config, transport_factory=self._transport_factory)
        if response.status_code in _REVOKED_STATUSES:
            return True
        refuse_an_unexpected_status(response, label=request.label)


def revocation_endpoint(config: ProviderConfig) -> str:
    """Return the revocation endpoint ``config`` declares.

    Args:
        config: The provider configuration to revoke against.

    Returns:
        The endpoint.

    Raises:
        ConfigurationError: If the configuration declares none.
    """
    # NOTE: An empty endpoint is refused on construction, and a copy of a configuration is not constructed.
    if not config.revocation_url:
        msg = "the provider configuration carries no revocation endpoint"
        raise ConfigurationError(msg)
    return config.revocation_url


def refuse_an_unexpected_status(response: httpx.Response, *, label: str | None) -> NoReturn:
    """Refuse a revocation response that states no outcome a handler can read.

    A provider documents the statuses it answers with, and any other status leaves the outcome
    unknown. A failure is classified as this library classifies any failed response, so a rate limit or
    an outage is not reported as the provider refusing to revoke a token it would revoke a minute later.
    A success the provider does not document states no outcome at all, and is refused as an answer this
    library cannot read rather than as the other side refusing the request.
    A response stating a temporary condition states nothing about the token either, whichever status
    carries it, so it is refused here rather than read as one of the statuses the provider documents.

    Args:
        response: The response whose status is classified.
        label: The provider's display name, which the message names, or ``None`` to name none.

    Raises:
        RevocationError: Always. Its kind says whether the same request may pass later.
    """
    failure = response_failure(response)
    subject = "token" if label is None else f"{label} token"
    if response.is_success:
        msg = f"Failed to revoke {subject}: the endpoint answered {failure.description}, which states no outcome"
        raise RevocationError(msg, kind=FailureKind.REFUSED)
    raise RevocationError(f"Failed to revoke {subject}: {failure.description}", kind=failure.kind)


def _refuse_an_unpermitted_url(request: RevocationRequest, config: ProviderConfig) -> None:
    """Refuse a request bound for a URL that must not be sent the token it carries.

    A handler builds the URL it sends to, so each URL the request names is read here rather than
    taken from the endpoint a validator saw.
    The rules apply in turn, and a refusal names the first one the URL breaks. The URL must name a
    host a request can be sent to. Its authority must be readable. Its authority must carry no
    credential of its own. It must protect the token in transit. Its host must be one that can
    answer for the token.
    A configuration naming no provider names no host the last rule could hold it to, as
    :meth:`~apron_auth.models.ProviderConfig.permits_revocation_at` says, and the rest still apply.
    NOTE: A URL no request can be sent to is refused here rather than left to the send, because the
    send reports it as an endpoint that may answer later and a misconfigured one never will.

    Args:
        request: The request about to be sent.
        config: The provider configuration to revoke against.

    Raises:
        ConfigurationError: If a URL the request names reaches no host, states an authority that
            cannot be read or that carries a credential, states a transport the configuration does
            not accept, or is on a host the configuration does not permit revocation at. The message
            names the host alone, because a URL can carry both the token and a credential of its own.
    """
    provider = config.provider
    plain_http_allowed = UrlField.REVOCATION_URL in config.allow_insecure_http_for
    for url in dict.fromkeys((request.url, request.endpoint or request.url)):
        host = url_host(url)
        if not host:
            msg = "Revocation refused: the request URL names no host a request can be sent to."
            raise ConfigurationError(msg)
        credential = authority_credential(url)
        match credential:
            case AuthorityCredential.ABSENT:
                pass
            case AuthorityCredential.MALFORMED:
                msg = f"Revocation refused: the authority of the request to {host} cannot be read."
                raise ConfigurationError(msg)
            case AuthorityCredential.PRESENT:
                # NOTE: An HTTP client derives client authentication from a URL's authority, and
                # presents it in place of the credential the request states rather than beside it.
                msg = (
                    f"Revocation refused: the request to {host} carries a credential in its URL. "
                    f"That credential would be presented in place of the token this request revokes."
                )
                raise ConfigurationError(msg)
            case _:
                assert_never(credential)
        if not uses_allowed_transport(url, plain_http_allowed=plain_http_allowed):
            msg = (
                f"Revocation refused: the request to {host} does not state a transport that protects "
                f"this token. It must state https, or http on a loopback host."
            )
            raise ConfigurationError(msg)
        if provider is None or config.permits_revocation_at(host):
            continue
        msg = (
            f"Revocation refused: the host {host} cannot answer for this token. A "
            f"{provider.display_name} token is revoked at the host that issued it, or at another "
            f"{provider.display_name} host."
        )
        raise ConfigurationError(msg)


def _presented_auth(auth: tuple[str, SecretStr] | None) -> tuple[str, str] | None:
    """Return an HTTP Basic credential in the form an HTTP client presents, or None to present none.

    NOTE: The result states the secret in plain text. It is owned by the call it is passed to and
    must not be bound to a local, because a local is what an error reporter records off a traceback.

    Args:
        auth: The credential to present, or ``None`` to present none.

    Returns:
        The ``(client_id, client_secret)`` pair as plain text, or ``None``.
    """
    if auth is None:
        return None
    return (auth[0], auth[1].get_secret_value())


async def send_revocation(
    request: RevocationRequest,
    config: ProviderConfig,
    *,
    transport_factory: TransportFactory | None = None,
) -> httpx.Response:
    """Send one revocation request and return the answer it gets.

    A provider reads success its own way, so this states no success rule and leaves the response to its caller.
    A response stating a temporary condition states no outcome for any provider to read, so it is
    refused here instead, and no handler can read it as a status of its own.
    The request carries a token, so this refuses a URL the configuration does not permit sending one
    to before it opens a connection.

    Args:
        request: What the provider states about the request.
        config: The provider configuration to revoke against, which decides the URLs the token may
            be sent to.
        transport_factory: Controls the outbound connection, and is called with the request's endpoint,
            which never carries the token. The URL is server-supplied, so a caller handling untrusted
            input can pin DNS to validated addresses here to prevent SSRF via rebinding.
            NOTE: The transport it returns is closed when the request completes, so a factory must not
            return one it intends to reuse.

    Returns:
        The endpoint's response, which states an outcome for its caller to read.

    Raises:
        ConfigurationError: If a URL the request names must not be sent the token, because it reaches
            no host, because its authority cannot be read or carries a credential of its own, because
            of the transport it states, or because of the host it names. Nothing is sent.
        RevocationError: If the request cannot be sent or fails to arrive, including where the
            transport refuses the URL it is given, or the endpoint answers an error status stating a
            temporary condition.
            Its kind says whether the same request may pass later.
            The caught error is not attached as its cause or context.
    """
    _refuse_an_unpermitted_url(request, config)
    subject = f"{request.label} token" if request.label is not None else "token"
    try:
        # Inside the try, so a factory that refuses cannot escape as itself, naming the URL it refused.
        transport = transport_factory(request.endpoint or request.url) if transport_factory is not None else None
        # A redirect would carry the token to a host the gate never read, so none is followed.
        async with httpx.AsyncClient(
            transport=transport, timeout=httpx_timeout(config.timeouts), follow_redirects=False
        ) as client:
            response = await within_request_limit(
                client.request(
                    request.method,
                    request.url,
                    auth=_presented_auth(request.auth),
                    data=request.data,
                    headers=request.headers,
                    json=request.json_body,
                    params=request.params,
                ),
                config.timeouts,
            )
    # NOTE: httpx.InvalidURL is not an httpx.HTTPError, so it needs its own clause.
    except httpx.InvalidURL:
        failure_message, kind = f"Failed to revoke {subject}: invalid URL", FailureKind.REFUSED
    except UnicodeEncodeError:
        # A token outside ASCII cannot go in a header, which no retry changes, and nothing left the process.
        failure_message, kind = f"Failed to revoke {subject}: the token could not be encoded", FailureKind.REFUSED
    except httpx.HTTPError as exc:
        failure = http_failure(exc)
        failure_message, kind = f"Failed to revoke {subject}: {failure.description}", failure.kind
    except Exception:
        # A failure outside the clauses above can still hold the token-bearing request.
        failure_message, kind = f"Failed to revoke {subject}: request failed", FailureKind.UNEXPECTED
    else:
        if httpx.codes.is_error(response.status_code) and response_failure(response).kind.retryable:
            refuse_an_unexpected_status(response, label=request.label)
        return response
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
        transport_factory: Controls the outbound connection for every revocation request, where a
            caller handling untrusted input can pin DNS to validated addresses.

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
    if provider is None or not config.revocation_url:
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
    return handler_class(transport_factory=transport_factory)
