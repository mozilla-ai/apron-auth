"""Types shared by the test suite."""

from __future__ import annotations

from typing import Protocol

from apron_auth.models import Provider

# One status each provider's revocation handler reads as the token revoked. No single status serves
# them all, because each provider documents its own and a handler refuses every status it does not
# state. A test about the request rather than the answer reads this so it reaches the happy path.
REVOKED_STATUS: dict[Provider, int] = {
    Provider.ATLASSIAN: 200,
    Provider.GITHUB: 204,
    Provider.GOOGLE: 200,
    Provider.HUBSPOT: 204,
    Provider.LINEAR: 200,
    Provider.MICROSOFT: 200,
    Provider.NOTION: 200,
    Provider.SALESFORCE: 200,
    Provider.SLACK: 200,
    Provider.TYPEFORM: 200,
}


class VaryFacts(Protocol):
    """Give a provider member different facts for the test that asks."""

    def __call__(self, provider: Provider, **changes: object) -> None:
        """Replace the named facts of ``provider`` for the duration of one test.

        Args:
            provider: The member whose facts differ in this test.
            changes: The facts to replace, named as :class:`~apron_auth.models.ProviderFacts` names them.
        """
        ...
