"""Every URL rule states where its value came from.

The class a refused URL raises follows the source: a value this library's caller passed is a
configuration fault, a value read out of a fetched document is a refusal of what the other side sent.
A default would pick one of those for a call site that forgot to say, so there is none.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from apron_auth.providers import _openid_documents

SRC = Path(_openid_documents.__file__).resolve().parents[1]


def _calls_without_a_source(path: Path) -> list[str]:
    """Return ``file:line`` for each ``require_url`` call that says nothing about its value's source."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or getattr(node.func, "id", None) != "require_url":
            continue
        keywords = {keyword.arg for keyword in node.keywords}
        # An issuer is always the caller's own value, so naming it states the source.
        if "caller_supplied" not in keywords and "is_issuer" not in keywords:
            found.append(f"{path.name}:{node.lineno}")
    return found


@pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC)))
def test_every_call_states_its_source(path: Path) -> None:
    assert _calls_without_a_source(path) == []


def test_the_guard_sees_a_call_that_says_nothing(tmp_path: Path) -> None:
    lines = [
        'require_url(url, field="x", allow_insecure_http=False)',
        'require_url(url, field="x", allow_insecure_http=False, caller_supplied=True)',
        'require_url(url, field="x", allow_insecure_http=False, is_issuer=True)',
    ]
    sample = tmp_path / "sample.py"
    sample.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert _calls_without_a_source(sample) == ["sample.py:1"]


def test_the_rule_takes_no_default_for_the_source() -> None:
    """A default would classify a forgotten call site rather than fail it."""
    parameter = inspect.signature(_openid_documents.require_url).parameters["caller_supplied"]

    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
