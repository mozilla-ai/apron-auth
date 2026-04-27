"""Regression fixture: ``disconnect_fully_revokes`` per provider preset.

The parameter on ``ProviderConfig`` is a *capability claim* that
consumers branch on to choose between automatic scope reduction
(tier 1) and a deep link to the provider's app-management page
(tier 3). Silently flipping a preset's value would change consumer UX
across the board, so this test pins the known-good value for every
preset and trips CI on any drift.

When a preset's verified behaviour genuinely changes, update both the
preset module's docstring (with the verification source) and the
``EXPECTED`` table below in the same commit.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from apron_auth.models import ProviderConfig
from apron_auth.providers import (
    atlassian,
    github,
    google,
    hubspot,
    linear,
    microsoft,
    notion,
    salesforce,
    slack,
    typeform,
)

EXPECTED: dict[str, tuple[Callable[..., tuple[ProviderConfig, object]], bool]] = {
    "google": (google.preset, True),
    "github": (github.preset, True),
    "slack": (slack.preset, True),
    "notion": (notion.preset, False),
    "linear": (linear.preset, False),
    "salesforce": (salesforce.preset, False),
    "typeform": (typeform.preset, False),
    "microsoft": (microsoft.preset, False),
    "atlassian": (atlassian.preset, False),
    "hubspot": (hubspot.preset, False),
}


@pytest.mark.parametrize(("name", "expected"), [(n, e) for n, (_, e) in EXPECTED.items()])
def test_preset_disconnect_fully_revokes_matches_fixture(name: str, expected: bool) -> None:
    """Each preset's ``disconnect_fully_revokes`` matches the pinned fixture."""
    factory, _ = EXPECTED[name]
    config, _ = factory(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        scopes=["dummy"],
    )
    assert config.disconnect_fully_revokes is expected


def test_provider_config_default_is_false() -> None:
    """``ProviderConfig`` defaults to ``False`` so unconfigured callers stay tier-3."""
    config = ProviderConfig(
        client_id="cid",
        client_secret="csecret",  # pragma: allowlist secret
        authorize_url="https://example.com/authorize",
        token_url="https://example.com/token",
    )
    assert config.disconnect_fully_revokes is False
