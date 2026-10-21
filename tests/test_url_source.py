"""A refused URL is classified by where its value came from.

A value this library's caller passed is a configuration fault, and one read out of a fetched document is a refusal.
Each call to a URL rule therefore names its value's source, and the signature is what enforces that.
A guard over the library states the convention in one place, and is the weaker of the two.
It reads a call by name, so it cannot tell whether the source a call names is the right one.
"""

from __future__ import annotations

import ast
import inspect
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from apron_auth.errors import FailureKind, OidcDiscoveryError
from apron_auth.mcp import _validate_url
from apron_auth.providers._openid_documents import require_url

if TYPE_CHECKING:
    from collections.abc import Callable

# Ordered so each constant follows the one it derives from.
# The library's source tree, which the guard walks alone so a test can still call a rule with no source.
SRC = Path(__file__).resolve().parents[1] / "src" / "apron_auth"
# Every module of that tree, one parametrized case each.
MODULES = sorted(SRC.rglob("*.py"))
# The two URL rules whose refusal follows the source of the value.
RULES = (_validate_url, require_url)
# The names the guard matches, read off the rules so a rename cannot leave it passing.
URL_RULES = {rule.__name__ for rule in RULES}
# A URL whose authority carries a credential the HTTP client would present.
_URL_WITH_CREDENTIAL = "https://operator:sesame@idp.example/token"  # pragma: allowlist secret


def _called_name(func: ast.expr) -> str | None:
    """Return the name a call targets, for a bare name or a qualified one such as ``module.x``."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _calls_without_a_source(path: Path) -> list[str]:
    """Return ``path:line`` for each call to a URL rule in ``path`` that says nothing about its value's source."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or _called_name(node.func) not in URL_RULES:
            continue
        if "caller_supplied" not in {keyword.arg for keyword in node.keywords}:
            found.append(f"{path}:{node.lineno}")
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

    assert _calls_without_a_source(sample) == [f"{sample}:{line}" for line in (1, 3, 4, 6)]


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.__name__)
def test_a_url_rule_takes_no_default_for_the_source(rule: Callable[..., object]) -> None:
    """A default would classify a forgotten call site rather than fail it."""
    parameter = inspect.signature(rule).parameters["caller_supplied"]

    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.parametrize(
    "call",
    [
        lambda: _validate_url("https://mcp.example.com/sse", None),
        lambda: require_url("https://idp.example/realm", field="endpoint", allow_insecure_http=False),
    ],
    ids=[rule.__name__ for rule in RULES],
)
def test_a_url_rule_refuses_a_call_that_names_no_source(call: Callable[[], object]) -> None:
    """The signature, not the guard over the library, is what a call site cannot get past."""
    with pytest.raises(TypeError, match="caller_supplied"):
        call()


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


def test_the_issuer_rules_refuse_a_query() -> None:
    """A query belongs to a request, not to the identifier every other URL is derived from."""
    with pytest.raises(OidcDiscoveryError, match="must not carry a query"):
        require_url(
            "https://idp.example/realm?tenant=acme",
            field="issuer",
            allow_insecure_http=False,
            caller_supplied=True,
            is_issuer=True,
        )


@pytest.mark.parametrize("is_issuer", [False, True], ids=["endpoint", "issuer"])
@pytest.mark.parametrize(
    ("caller_supplied", "expected"),
    [(False, FailureKind.REFUSED), (True, FailureKind.CONFIGURATION)],
    ids=["document", "caller"],
)
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(_URL_WITH_CREDENTIAL, id="a user and a password"),
        pytest.param("https://operator@idp.example/token", id="a user alone"),
        pytest.param("https://@idp.example/token", id="an empty user"),
    ],
)
def test_every_url_refuses_a_credential_in_its_authority(
    value: str, caller_supplied: bool, expected: FailureKind, is_issuer: bool
) -> None:
    """A delimiter in the authority is refused whether or not it carries a value, so the rule stays one rule."""
    with pytest.raises(OidcDiscoveryError, match="must not carry userinfo") as exc_info:
        require_url(
            value,
            field="token endpoint",
            allow_insecure_http=False,
            caller_supplied=caller_supplied,
            is_issuer=is_issuer,
        )

    assert exc_info.value.kind is expected


def test_a_refused_credential_reaches_neither_the_error_nor_its_traceback() -> None:
    """The refusal reaches a log and a caller's error reporter, so it must not repeat what it refused."""
    with pytest.raises(OidcDiscoveryError) as exc_info:
        require_url(_URL_WITH_CREDENTIAL, field="token endpoint", allow_insecure_http=False, caller_supplied=True)

    rendered = "".join(traceback.format_exception(exc_info.value))
    assert "operator" not in rendered
    assert "sesame" not in rendered


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("https://idp.example\x00/realm", id="a non-printable character"),
        pytest.param("https://idp\texample.com/realm", id="a control character"),
        pytest.param("https://\u2026.example/realm", id="a host with no IDNA form"),
    ],
)
def test_a_url_that_cannot_be_requested_is_refused_by_its_source(value: str) -> None:
    """A URL the request itself would reject is the caller's fault when the caller passed it."""
    with pytest.raises(OidcDiscoveryError, match="is malformed") as exc_info:
        require_url(value, field="document URL", allow_insecure_http=False, caller_supplied=True)

    assert exc_info.value.kind is FailureKind.CONFIGURATION


# The one module allowed to decide whether an authority carries a credential.
CREDENTIAL_RULE = "_urls.py"


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.name)
def test_only_one_module_decides_whether_an_authority_carries_a_credential(module: Path) -> None:
    """Five rules refuse a credential in an authority, and a sixth definition of one would not be checked."""
    if module.name == CREDENTIAL_RULE:
        return
    tree = ast.parse(module.read_text(), filename=str(module))
    reads = [
        node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in {"username", "password"}
    ]

    assert reads == [], f"{module.name} reads the authority itself; call authority_credential instead"
