"""The library's logging contract: silent by default, configurable by name."""

from __future__ import annotations

import logging
import subprocess
import sys

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
