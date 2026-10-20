from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from apron_auth._clock import CLOCK_SKEW_SECONDS, PendingAgeRefusalReason, pending_age_refusal
from apron_auth.client import _check_pending_age
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
_CASES: tuple[tuple[str, object, PendingAgeRefusalReason | None], ...] = (
    ("the clock reading itself", _NOW, None),
    ("exactly the limit old", _NOW - _LIMIT, None),
    ("just inside the limit", _NOW - _LIMIT + 0.001, None),
    ("just past the limit", _NOW - _LIMIT - 0.001, PendingAgeRefusalReason.TOO_OLD),
    ("exactly the clock difference ahead", _NOW + CLOCK_SKEW_SECONDS, None),
    ("just past the clock difference", _NOW + CLOCK_SKEW_SECONDS + 0.001, PendingAgeRefusalReason.AHEAD_OF_CLOCK),
    ("beyond the float range", 10**400, PendingAgeRefusalReason.AHEAD_OF_CLOCK),
    ("negatively beyond the float range", -(10**400), PendingAgeRefusalReason.TOO_OLD),
    ("infinite", math.inf, PendingAgeRefusalReason.UNUSABLE),
    ("negatively infinite", -math.inf, PendingAgeRefusalReason.UNUSABLE),
    ("not a number", math.nan, PendingAgeRefusalReason.UNUSABLE),
    ("a boolean", True, PendingAgeRefusalReason.UNUSABLE),
    ("a string", "600", PendingAgeRefusalReason.UNUSABLE),
    ("absent", None, PendingAgeRefusalReason.UNUSABLE),
)

_CREATION_TIMES = [pytest.param(created_at, reason, id=name) for name, created_at, reason in _CASES]


class TestPendingAgeRefusal:
    """Test which clock condition a creation time fails, with each limit refusing only what lies past it."""

    @pytest.mark.parametrize(("created_at", "reason"), _CREATION_TIMES)
    def test_the_reason_a_creation_time_is_not_current(
        self, monkeypatch: pytest.MonkeyPatch, created_at: object, reason: PendingAgeRefusalReason | None
    ) -> None:
        _freeze_clock(monkeypatch)

        assert pending_age_refusal(created_at, max_age=_LIMIT) is reason


class TestTheStoreAndTheAgeCheckAgree:
    """Test that one creation time means the same thing to the reference store and to the age check."""

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

    def test_every_reason_reaches_a_caller_as_its_own_refusal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A reason worded like another, or not worded at all, leaves a caller unable to tell them apart."""
        _freeze_clock(monkeypatch)
        wordings: dict[PendingAgeRefusalReason, str] = {}
        for _, created_at, reason in _CASES:
            if reason is None:
                continue
            with pytest.raises(StateError) as caught:
                _check_pending_age(_pending(created_at), max_age=_LIMIT)
            wordings[reason] = str(caught.value)

        assert set(wordings) == set(PendingAgeRefusalReason)
        assert all(wordings.values())
        assert len(set(wordings.values())) == len(PendingAgeRefusalReason)
