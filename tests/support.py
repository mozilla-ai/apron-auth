"""Types shared by the test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from apron_auth.models import Provider


class VaryFacts(Protocol):
    """Give a provider member different facts for the test that asks."""

    def __call__(self, provider: Provider, **changes: object) -> None:
        """Replace the named facts of ``provider`` for the duration of one test.

        Args:
            provider: The member whose facts differ in this test.
            changes: The facts to replace, named as :class:`~apron_auth.models.ProviderFacts` names them.
        """
        ...
