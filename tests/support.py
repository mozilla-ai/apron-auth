"""Types shared by the test suite."""

from __future__ import annotations

from typing import Protocol

from apron_auth.models import Provider

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
