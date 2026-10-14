from __future__ import annotations

import pytest

from apron_auth._discovery import str_list


class TestStrList:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (["a", "b"], ["a", "b"]),
            (["a", 1, None, "b"], ["a", "b"]),
            ([], []),
            (None, []),
            ("not-a-list", []),
            ({"a": 1}, []),
        ],
    )
    def test_filters_to_strings(self, value: object, expected: list[str]) -> None:
        assert str_list(value) == expected
