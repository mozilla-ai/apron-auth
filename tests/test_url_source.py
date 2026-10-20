"""Every URL rule states where its value came from.

The class a refused URL raises follows the source of its value.
A value this library's caller passed is a configuration fault,
and one read out of a fetched document is a refusal of what the other side sent.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from apron_auth.mcp import _validate_url
from apron_auth.providers._openid_documents import require_url

if TYPE_CHECKING:
    from collections.abc import Callable

# The library's source tree, walked to hold every call to a URL rule to the convention.
SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"
# The URL rules whose refusal follows the source, so every call to one names it.
URL_RULES = {"_validate_url", "require_url"}


def _called_name(func: ast.expr) -> str | None:
    """Return the name a call targets, for a bare name or a qualified one such as ``module.x``."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _calls_without_a_source(path: Path) -> list[str]:
    """Return ``file:line`` for each call to a URL rule in ``path`` that says nothing about its value's source."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or _called_name(node.func) not in URL_RULES:
            continue
        if "caller_supplied" not in {keyword.arg for keyword in node.keywords}:
            found.append(f"{path.name}:{node.lineno}")
    return found


@pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC)))
def test_every_call_states_its_source(path: Path) -> None:
    assert _calls_without_a_source(path) == []


def test_the_guard_sees_a_call_that_says_nothing(tmp_path: Path) -> None:
    """Naming the issuer does not state the source, and a qualified call is checked like a bare one."""
    lines = [
        'require_url(url, field="x", allow_insecure_http=False)',
        'require_url(url, field="x", allow_insecure_http=False, caller_supplied=True)',
        'require_url(url, field="x", allow_insecure_http=False, is_issuer=True)',
        '_openid_documents.require_url(url, field="x", allow_insecure_http=False)',
        '_openid_documents.require_url(url, field="x", allow_insecure_http=False, caller_supplied=False)',
        "_validate_url(url, None)",
        "_validate_url(url, None, caller_supplied=True)",
    ]
    sample = tmp_path / "sample.py"
    sample.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert _calls_without_a_source(sample) == ["sample.py:1", "sample.py:3", "sample.py:4", "sample.py:6"]


@pytest.mark.parametrize("rule", [_validate_url, require_url], ids=lambda rule: rule.__name__)
def test_a_url_rule_takes_no_default_for_the_source(rule: Callable[..., object]) -> None:
    """A default would classify a forgotten call site rather than fail it."""
    parameter = inspect.signature(rule).parameters["caller_supplied"]

    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
