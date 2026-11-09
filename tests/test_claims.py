from __future__ import annotations

import pytest

from apron_auth._claims import stated_boolean


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
