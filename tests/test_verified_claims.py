"""A claim stating whether a provider verified something is read by one rule.

Such a claim is documented as a boolean and arrives as untrusted input, so coercing it reads the string
``"false"`` as verified, which asserts the opposite of what the provider wrote. One rule states what a
value of another type means, and this guard holds every reader of such a claim to it, because the
alternative is a reader written by whichever idiom its author happened to open.
The guard matches a read by the member's name, so it cannot tell whether the reader then acts on the
answer correctly.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from apron_auth._claims import stated_boolean

# Ordered so each constant follows the one it derives from.
# The library's source tree, which the guard walks alone so a test can still read a claim directly.
SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"
# The module that states the rule, which is the one place a read may be unwrapped.
RULE_FILE = "_claims.py"
# Every other module of that tree, one parametrized case each.
MODULES = sorted(path for path in SRC.rglob("*.py") if path.name != RULE_FILE)
# The members a provider states a verification in. A member naming a preference between values is not one.
VERIFICATION_MEMBERS = frozenset({"email_verified", "verified"})
# The rule's own name, read off it so a rename cannot leave this guard passing.
RULE = stated_boolean.__name__
# Where the rule is stated, so a module cannot satisfy this guard with a name of its own.
RULE_MODULE = stated_boolean.__module__


def _member_read(node: ast.AST) -> str | None:
    """Return the verification member a node reads, for a ``get`` call or a subscript, else ``None``."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant) and first.value in VERIFICATION_MEMBERS:
            return str(first.value)
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and node.slice.value in VERIFICATION_MEMBERS
    ):
        return str(node.slice.value)
    return None


def _calls_the_rule(node: ast.AST) -> bool:
    """Whether a node calls the rule, named on its own or through the module that states it."""
    if not isinstance(node, ast.Call) or not node.args:
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id == RULE
    return isinstance(node.func, ast.Attribute) and node.func.attr == RULE


def _takes_the_rule_from_where_it_is_stated(tree: ast.Module) -> bool:
    """Whether the module imports the rule, rather than naming something of its own the same."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == RULE_MODULE
            and any(alias.name == RULE and alias.asname is None for alias in node.names)
        ):
            return True
        if isinstance(node, ast.Import) and any(alias.name == RULE_MODULE for alias in node.names):
            return True
    return False


def _reads_outside_the_rule(path: Path) -> list[str]:
    """Return ``path:line`` for each read of a verification member in ``path`` that the rule does not answer."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    reads = [node for node in ast.walk(tree) if _member_read(node) is not None]
    if not reads:
        return []
    if not _takes_the_rule_from_where_it_is_stated(tree):
        return [f"{path}: states a name of its own for the rule"]
    answered = {id(node.args[0]) for node in ast.walk(tree) if _calls_the_rule(node)}
    return [f"{path}:{node.lineno}" for node in reads if id(node) not in answered]


def test_the_walk_reaches_the_library() -> None:
    """A walk that reaches nothing parametrizes no case, which pytest reports as a skip rather than a failure."""
    assert MODULES


def test_the_walk_reaches_a_reader() -> None:
    """A guard that matches no read anywhere would pass whatever the readers did."""
    assert [path for path in MODULES if "email_verified" in path.read_text(encoding="utf-8")]


@pytest.mark.parametrize("path", MODULES, ids=lambda path: str(path.relative_to(SRC)))
def test_every_read_of_a_verification_goes_through_the_rule(path: Path) -> None:
    assert _reads_outside_the_rule(path) == []
