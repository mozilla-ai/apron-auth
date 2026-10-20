"""A refused URL is classified by where its value came from.

A value this library's caller passed is a configuration fault,
and one read out of a fetched document is a refusal of what the other side sent.
Each call to a URL rule therefore names its value's source, which a guard over the library's
own source reads syntactically: it holds every call to the convention, not to a correct answer.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from apron_auth.errors import FailureKind, OidcDiscoveryError
from apron_auth.mcp import _validate_url
from apron_auth.providers._openid_documents import require_url

if TYPE_CHECKING:
    from collections.abc import Callable

# The library's source tree, walked to hold every call to a URL rule to the convention.
SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"
# Every module of that tree, one parametrized case each.
MODULES = sorted(SRC.rglob("*.py"))
# The URL rules whose refusal follows the source, named so a rename cannot leave the guard passing.
URL_RULES = {rule.__name__ for rule in (_validate_url, require_url)}


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


def test_the_walk_reaches_the_library() -> None:
    """A walk that reaches nothing parametrizes no case, which pytest reports as a skip rather than a failure."""
    assert MODULES


@pytest.mark.parametrize("path", MODULES, ids=lambda p: str(p.relative_to(SRC)))
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


@pytest.mark.parametrize("is_issuer", [False, True], ids=["endpoint", "issuer"])
@pytest.mark.parametrize(
    ("caller_supplied", "expected"),
    [(False, FailureKind.REFUSED), (True, FailureKind.CONFIGURATION)],
    ids=["document", "caller"],
)
def test_the_source_alone_decides_the_kind(caller_supplied: bool, expected: FailureKind, is_issuer: bool) -> None:
    with pytest.raises(OidcDiscoveryError) as exc_info:
        require_url(
            "http://idp.example/endpoint",
            field="endpoint",
            allow_insecure_http=False,
            caller_supplied=caller_supplied,
            is_issuer=is_issuer,
        )

    assert exc_info.value.kind is expected


def test_the_issuer_flag_selects_rules_and_not_a_source() -> None:
    """An issuer carries no query, and a value the caller passed stays the caller's either way."""
    with_a_query = "https://idp.example/endpoint?tenant=acme"
    require_url(with_a_query, field="endpoint", allow_insecure_http=False, caller_supplied=True)

    with pytest.raises(OidcDiscoveryError, match="must not carry a query") as exc_info:
        require_url(with_a_query, field="issuer", allow_insecure_http=False, caller_supplied=True, is_issuer=True)

    assert exc_info.value.kind is FailureKind.CONFIGURATION
