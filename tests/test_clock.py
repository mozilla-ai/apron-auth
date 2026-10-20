from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from apron_auth._clock import CLOCK_SKEW_SECONDS, PendingAgeRefusalReason, pending_age_refusal
from apron_auth.client import _PENDING_AGE_REFUSALS, _check_pending_age
from apron_auth.errors import StateError
from apron_auth.models import OAuthPendingState
from apron_auth.stores import MemoryStateStore

_LIMIT = 300.0
_NOW = 1_700_000_000.0


def _freeze_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the clock the rule reads to ``_NOW``."""
    monkeypatch.setattr("apron_auth._clock.time", SimpleNamespace(time=lambda: _NOW))


def _pending(created_at: object) -> OAuthPendingState:
    """Return a pending request carrying ``created_at``, built without validation."""
    return OAuthPendingState.model_construct(
        state="state-key",
        redirect_uri="https://app.example.com/callback",
        code_verifier="test-verifier",
        created_at=created_at,
    )


# Each creation time with the reason it fails, or ``None`` when it is still current.
_CREATION_TIMES = [
    pytest.param(_NOW, None, id="the clock reading itself"),
    pytest.param(_NOW - _LIMIT, None, id="exactly the limit old"),
    pytest.param(_NOW - _LIMIT + 0.001, None, id="just inside the limit"),
    pytest.param(_NOW - _LIMIT - 0.001, PendingAgeRefusalReason.TOO_OLD, id="just past the limit"),
    pytest.param(_NOW + CLOCK_SKEW_SECONDS, None, id="exactly the clock difference ahead"),
    pytest.param(
        _NOW + CLOCK_SKEW_SECONDS + 0.001,
        PendingAgeRefusalReason.AHEAD_OF_CLOCK,
        id="just past the clock difference",
    ),
    pytest.param(10**400, PendingAgeRefusalReason.AHEAD_OF_CLOCK, id="beyond the float range"),
    pytest.param(-(10**400), PendingAgeRefusalReason.TOO_OLD, id="negatively beyond the float range"),
    pytest.param(math.inf, PendingAgeRefusalReason.UNUSABLE, id="infinite"),
    pytest.param(-math.inf, PendingAgeRefusalReason.UNUSABLE, id="negatively infinite"),
    pytest.param(math.nan, PendingAgeRefusalReason.UNUSABLE, id="not a number"),
    pytest.param(True, PendingAgeRefusalReason.UNUSABLE, id="a boolean"),
    pytest.param("600", PendingAgeRefusalReason.UNUSABLE, id="a string"),
    pytest.param(None, PendingAgeRefusalReason.UNUSABLE, id="absent"),
]


class TestPendingAgeRefusal:
    """Test which clock condition a creation time fails, with each limit refusing only what lies past it."""

    @pytest.mark.parametrize(("created_at", "reason"), _CREATION_TIMES)
    def test_the_reason_a_creation_time_is_not_current(
        self, monkeypatch: pytest.MonkeyPatch, created_at: object, reason: PendingAgeRefusalReason | None
    ) -> None:
        _freeze_clock(monkeypatch)

        assert pending_age_refusal(created_at, max_age=_LIMIT) is reason


class TestTheStoreAndTheExchangeAgree:
    """Test that one creation time means the same thing to the reference store and to the code exchange."""

    @pytest.mark.parametrize(("created_at", "reason"), _CREATION_TIMES)
    async def test_the_store_drops_what_the_exchange_refuses(
        self, monkeypatch: pytest.MonkeyPatch, created_at: object, reason: PendingAgeRefusalReason | None
    ) -> None:
        _freeze_clock(monkeypatch)
        pending = _pending(created_at)
        store = MemoryStateStore(max_age=_LIMIT)
        await store.save(pending)

        dropped = await store.consume(pending.state) is None
        refused = False
        try:
            _check_pending_age(pending, max_age=_LIMIT)
        except StateError:
            refused = True

        assert dropped is (reason is not None)
        assert refused is (reason is not None)

    def test_the_exchange_words_every_reason(self) -> None:
        assert set(_PENDING_AGE_REFUSALS) == set(PendingAgeRefusalReason)
