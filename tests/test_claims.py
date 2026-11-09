from __future__ import annotations

import pytest

from apron_auth._claims import stated_boolean, stated_string


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_boolean_is_what_it_states(value: bool) -> None:
    assert stated_boolean(value) is value


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("false", id="the string false"),
        pytest.param("true", id="the string true"),
        pytest.param("", id="an empty string"),
        pytest.param(1, id="the number one"),
        pytest.param(0, id="the number zero"),
        pytest.param(None, id="nothing at all"),
        pytest.param([], id="an empty list"),
        pytest.param(["true"], id="a list"),
        pytest.param({}, id="an empty object"),
        pytest.param({"value": True}, id="an object"),
    ],
)
def test_a_value_of_another_type_states_no_boolean(value: object) -> None:
    """A coercion would read the string ``"false"`` as ``True``, which asserts the opposite of itself."""
    assert stated_boolean(value) is None


@pytest.mark.parametrize(
    "value",
    [
        pytest.param({"address": "a@b.c"}, id="an object"),
        pytest.param(["a@b.c"], id="a list"),
        pytest.param(7, id="a number"),
        pytest.param(True, id="a boolean"),
        pytest.param(None, id="nothing at all"),
        pytest.param("", id="an empty string"),
    ],
)
def test_a_value_that_is_no_text_states_none(value: object) -> None:
    """Rendering one as text would put whatever arrived into the field that reports it."""
    assert stated_string(value) is None


def test_text_is_what_it_states() -> None:
    assert stated_string("a@b.c") == "a@b.c"
