"""Types shared by the test suite."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol

import httpx

from apron_auth.models import Provider

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

# A success status every revocation handler reads as the token revoked, unless its provider is named below.
ANY_SUCCESS_STATUS = 200

# The providers whose own handler reads a narrower set, because each provider documents its own statuses
# and a handler refuses every status it does not state. A provider absent from here takes RFC 7009
# revocation, or its own handler reads any success.
_NARROWER_REVOKED_STATUS: dict[Provider, int] = {Provider.GITHUB: 204, Provider.HUBSPOT: 204}


def revoked_status(provider: Provider) -> int:
    """Return a status ``provider``'s revocation handler reads as the token revoked.

    A test about the request rather than the answer reads this, so it reaches the happy path instead of a
    refusal of a status the handler under test does not state.

    Args:
        provider: The provider whose handler answers.

    Returns:
        The status to answer with.
    """
    return _NARROWER_REVOKED_STATUS.get(provider, ANY_SUCCESS_STATUS)


class VaryFacts(Protocol):
    """Give a provider member different facts for the test that asks."""

    def __call__(self, provider: Provider, **changes: object) -> None:
        """Replace the named facts of ``provider`` for the duration of one test.

        Args:
            provider: The member whose facts differ in this test.
            changes: The facts to replace, named as :class:`~apron_auth.models.ProviderFacts` names them.
        """
        ...


class LazyByteStream(httpx.AsyncByteStream):
    """A response body that yields its chunks one at a time, counting what a reader pulled.

    A mock transport materializes a whole body, so a reader that holds everything it is given passes
    against one. This yields on demand, so a test can state what a reader pulled and what it did not.

    Attributes:
        closed: Whether the body was released, which a reader that stops before the end must do.
        pulled: The bytes yielded so far, as they arrive on the wire.
    """

    def __init__(self, chunks: Sequence[bytes], *, chunk_seconds: float = 0.0) -> None:
        """Create the body.

        Args:
            chunks: The chunks to yield, in order.
            chunk_seconds: How long to wait before each chunk, for a body that arrives slowly.
        """
        self._chunks = chunks
        self._chunk_seconds = chunk_seconds
        self.closed = False
        self.pulled = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield each chunk in turn, waiting first where the body arrives slowly.

        Yields:
            The next chunk.
        """
        for chunk in self._chunks:
            if self._chunk_seconds:
                await asyncio.sleep(self._chunk_seconds)
            self.pulled += len(chunk)
            yield chunk

    async def aclose(self) -> None:
        """Release the body, which holds nothing to release but records that it was asked."""
        self.closed = True


class LazyBodyTransport(httpx.AsyncBaseTransport):
    """A transport answering every request with one lazily yielded body, holding what it answered with.

    A reader that fails states no response of its own, so a test about what became of one reads it here.

    Attributes:
        answered: Each response this answered with, in order.
    """

    def __init__(self, stream: LazyByteStream, *, headers: Mapping[str, str] | None = None) -> None:
        """Create the transport.

        Args:
            stream: The body every response states.
            headers: The headers every response states.
        """
        self._stream = stream
        self._headers = dict(headers or {"content-type": "application/json"})
        self.answered: list[httpx.Response] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Answer ``request`` with the lazily yielded body.

        Args:
            request: The request to answer.

        Returns:
            The response, whose body has not been read.
        """
        response = httpx.Response(200, headers=self._headers, stream=self._stream)
        self.answered.append(response)
        return response
