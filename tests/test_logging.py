"""The library's logging contract: silent by default, configurable by name."""

from __future__ import annotations

import ast
import logging
import subprocess
import sys
from pathlib import Path

import pytest

import apron_auth


def test_library_logger_has_null_handler():
    """The package root carries a NullHandler so records find a handler.

    Without one, ``logging.lastResort`` writes WARNING and above to the
    consumer's stderr when the application has configured no logging.
    """
    root = logging.getLogger("apron_auth")
    assert any(isinstance(handler, logging.NullHandler) for handler in root.handlers)


def test_library_configures_nothing_else():
    """Importing the library must not configure logging on the caller's behalf.

    A library that sets a level or attaches a real handler overrides
    choices that belong to the application.
    """
    root = logging.getLogger("apron_auth")
    assert root.level == logging.NOTSET
    assert all(isinstance(handler, logging.NullHandler) for handler in root.handlers)


def test_warning_is_silent_in_an_unconfigured_application():
    """A warning must not reach stderr when the application configures nothing.

    Run in a subprocess because both the last-resort fallback and the
    root logger's handlers are global state that the test runner itself
    configures, which would mask what a plain interpreter would do.
    """
    source = (
        "import logging, apron_auth\n"
        "assert not logging.getLogger().handlers, 'import configured the root logger'\n"
        "logging.getLogger('apron_auth.providers.microsoft').warning('should not be seen')\n"
    )
    result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True, check=True)

    assert result.stderr == ""
    assert result.stdout == ""


def test_application_can_still_capture_library_warnings(caplog):
    """Configuring the ``apron_auth`` logger must surface records normally.

    The NullHandler suppresses only the last-resort fallback; it must not
    make the library unloggable.
    """
    with caplog.at_level(logging.WARNING, logger="apron_auth"):
        logging.getLogger("apron_auth.providers.microsoft").warning("degraded capability")

    assert "degraded capability" in caplog.text


def test_public_api_import_is_unaffected():
    """The logging setup must not disturb the package's exports."""
    assert "OAuthClient" in apron_auth.__all__


_LOG_METHODS = frozenset({"critical", "debug", "error", "exception", "info", "log", "warning"})


def _is_logger(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return "log" in node.id.lower()
    if isinstance(node, ast.Attribute):
        return "log" in node.attr.lower()
    return isinstance(node, ast.Call) and _is_logger(node.func)


def _is_log_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _LOG_METHODS
        and _is_logger(node.func.value)
    )


def _renders_the_current_exception(node: ast.AST) -> bool:
    """Return whether an expression reads the exception being handled without naming it."""
    return isinstance(node, ast.Attribute) and (
        (isinstance(node.value, ast.Name) and node.value.id == "traceback")
        or (isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr in {"exc_info", "exception"})
    )


def _is_safe_use(name: ast.Name, parents: dict[ast.AST, ast.AST]) -> bool:
    """Return whether a use of a caught exception in a log call reads only a primitive that holds no secret."""
    parent = parents[name]
    grandparent = parents.get(parent)
    if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and name in parent.args:
        if parent.func.id == "http_failure":
            return isinstance(grandparent, ast.Attribute) and grandparent.attr == "description"
        return parent.func.id == "type" and isinstance(grandparent, ast.Attribute) and grandparent.attr == "__name__"
    return (
        isinstance(parent, ast.Attribute)
        and parent.attr == "response"
        and isinstance(grandparent, ast.Attribute)
        and grandparent.attr == "status_code"
    )


def _logged_exceptions(source: str) -> list[int]:
    """Return the line of each log call that can render a caught exception's value."""
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    lines: set[int] = set()
    for call in filter(_is_log_call, ast.walk(tree)):
        if call.func.attr == "exception" or any(_renders_the_current_exception(node) for node in ast.walk(call)):
            lines.add(call.lineno)
        for keyword in call.keywords:
            disabled = isinstance(keyword.value, ast.Constant) and keyword.value.value in (False, None)
            if keyword.arg in {"exc_info", "stack_info"} and not disabled:
                lines.add(call.lineno)
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or handler.name is None:
            continue
        for call in filter(_is_log_call, ast.walk(handler)):
            for name in ast.walk(call):
                if isinstance(name, ast.Name) and name.id == handler.name and not _is_safe_use(name, parents):
                    lines.add(call.lineno)
    return sorted(lines)


@pytest.mark.parametrize(
    "log_call",
    [
        'logger.warning("failed: %s", exc)',
        'logger.warning("failed: %s", str(exc))',
        'logger.warning(f"failed: {exc}")',
        'logger.warning("failed: %s", exc.args)',
        'logger.warning("failed: %s", exc.response.text)',
        'logger.warning("failed: %s", type(exc))',
        'logger.warning("failed: %s", traceback.format_exc())',
        'logger.warning("failed: %s", sys.exc_info()[1])',
        'logger.debug("failed", exc_info=exc)',
        'logger.debug("failed", exc_info=True)',
        'logger.debug("failed", stack_info=True)',
        'logger.exception("failed")',
        'log.warning("failed: %s", exc)',
        'self._logger.warning("failed: %s", exc)',
        'logging.getLogger(__name__).warning("failed: %s", exc)',
    ],
)
def test_the_scan_finds_a_log_call_that_renders_an_exception(log_call: str) -> None:
    source = f"try:\n    pass\nexcept Exception as exc:\n    {log_call}\n"

    assert _logged_exceptions(source) == [4]


@pytest.mark.parametrize(
    "log_call",
    [
        'logger.warning("failed (%s)", http_failure(exc).description)',
        'logger.warning("failed (status %s)", exc.response.status_code)',
        'logger.debug("failed (%s)", type(exc).__name__)',
        'logger.warning("failed")',
        'logger.debug("failed", exc_info=False)',
    ],
)
def test_the_scan_allows_a_log_call_that_reads_only_a_safe_primitive(log_call: str) -> None:
    source = f"try:\n    pass\nexcept Exception as exc:\n    {log_call}\n"

    assert _logged_exceptions(source) == []


@pytest.mark.parametrize(
    "path",
    sorted(Path(apron_auth.__file__).parent.rglob("*.py")),
    ids=lambda path: str(path.relative_to(Path(apron_auth.__file__).parent)),
)
def test_no_log_call_renders_an_exception_value(path: Path) -> None:
    """An exception's rendering can hold the request that carried a credential, so no log line may include it.

    NOTE: The scan reads only a log call's own arguments, so an exception stored in another variable first is not seen.
    """
    assert _logged_exceptions(path.read_text(encoding="utf-8")) == []
