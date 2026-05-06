"""Shared types for identity-resolver registration."""

from __future__ import annotations

from dataclasses import dataclass

from apron_auth.protocols import IdentityResolver

# Module-level export name that provider modules use to register
# identity inference declaratively,
# e.g. ``IDENTITY_RESOLVER = IdentityResolverRegistration(...)``.
IDENTITY_RESOLVER_ATTR = "IDENTITY_RESOLVER"


@dataclass(frozen=True)
class IdentityResolverRegistration:
    """Declarative registration entry for provider identity inference."""

    provider: str
    resolver: IdentityResolver
