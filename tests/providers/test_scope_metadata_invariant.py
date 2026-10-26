"""Cross-provider invariant: preset-injected scopes must carry metadata.

Every preset that injects cross-cutting OAuth scopes — scopes the
consumer didn't pass in — must also declare matching ``ScopeMetadata``
so a consent picker can render every entry in ``ProviderConfig.scopes``
without a hand-maintained parallel table.

This test diffs ``ProviderConfig.scopes`` against the consumer-passed
scope set for every preset and asserts the difference is fully covered
by ``ProviderConfig.scope_metadata``.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

import pytest

from apron_auth.models import ServerMetadata
from apron_auth.providers import (
    atlassian,
    github,
    google,
    hubspot,
    linear,
    microsoft,
    notion,
    oidc,
    salesforce,
    slack,
    typeform,
)

PROBE_CONSUMER_SCOPES = ["caller.read"]

# A generic OpenID preset takes discovered metadata rather than hardcoding endpoints.
PROBE_OIDC_METADATA = ServerMetadata(
    authorize_url="https://sso.example.com/auth",
    token_url="https://sso.example.com/token",
    issuer="https://sso.example.com",
    jwks_url="https://sso.example.com/certs",
)


PRESETS: list[tuple[str, Callable[..., tuple]]] = [
    ("atlassian", atlassian.preset),
    ("github", github.preset),
    ("google", google.preset),
    ("hubspot", hubspot.preset),
    ("linear", linear.preset),
    ("microsoft", microsoft.preset),
    ("notion", notion.preset),
    ("oidc", partial(oidc.preset, metadata=PROBE_OIDC_METADATA)),
    ("salesforce", salesforce.preset),
    ("slack", slack.preset),
    ("typeform", typeform.preset),
]


@pytest.mark.parametrize(("name", "preset_fn"), PRESETS, ids=[name for name, _ in PRESETS])
def test_injected_scopes_have_matching_metadata(name: str, preset_fn: Callable[..., tuple]):
    config = preset_fn(
        client_id=f"{name}-id",
        client_secret=f"{name}-secret",  # pragma: allowlist secret
        scopes=list(PROBE_CONSUMER_SCOPES),
    )
    injected = set(config.scopes) - set(PROBE_CONSUMER_SCOPES)
    declared = {meta.scope for meta in config.scope_metadata}
    missing = injected - declared
    assert not missing, f"{name} preset injects scopes without ScopeMetadata: {sorted(missing)}"


@pytest.mark.parametrize(("name", "preset_fn"), PRESETS, ids=[name for name, _ in PRESETS])
def test_scope_metadata_only_describes_injected_scopes(name: str, preset_fn: Callable[..., tuple]):
    """Presets must not declare metadata for scopes they don't own.

    apron-tools owns tool-level scope metadata; apron-auth presets only
    declare metadata for the cross-cutting scopes they themselves inject.
    Declaring metadata for a caller-passed scope would create the same
    drift problem the consent-picker design is meant to avoid.
    """
    config = preset_fn(
        client_id=f"{name}-id",
        client_secret=f"{name}-secret",  # pragma: allowlist secret
        scopes=list(PROBE_CONSUMER_SCOPES),
    )
    declared = {meta.scope for meta in config.scope_metadata}
    overlap = declared & set(PROBE_CONSUMER_SCOPES)
    assert not overlap, f"{name} preset declared metadata for caller-passed scopes: {sorted(overlap)}"
