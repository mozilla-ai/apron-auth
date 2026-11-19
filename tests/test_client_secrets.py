"""The rule that decides what counts as no client secret answers presence, and hands back no plaintext.

A caller asking whether a secret is present has no use for the secret, and a value it is handed is a
value it can bind to a local, which an error reporter records off a traceback.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from apron_auth._client_secrets import stated_client_secret

# A secret distinctive enough that finding it in a value cannot be a coincidence.
SECRET = "s3cr3t-client-secret"  # pragma: allowlist secret


class TestStatedClientSecret:
    def test_a_present_wrapper_is_handed_back_as_the_wrapper(self) -> None:
        """The wrapper states nothing as text, so handing it back states nothing to its caller."""
        secret = SecretStr(SECRET)
        assert stated_client_secret(secret) is secret

    @pytest.mark.parametrize("value", [None, "", "   ", "\t\n"])
    def test_a_value_that_states_nothing_reads_as_absent(self, value: str | None) -> None:
        assert stated_client_secret(value) is None

    @pytest.mark.parametrize("value", [SecretStr(None), SecretStr(""), SecretStr("   ")])  # ty: ignore[invalid-argument-type]
    def test_a_wrapper_that_states_nothing_reads_as_absent(self, value: SecretStr) -> None:
        assert stated_client_secret(value) is None

    def test_a_plain_string_is_handed_back_for_the_field_to_wrap(self) -> None:
        assert stated_client_secret(SECRET) == SECRET

    @pytest.mark.parametrize("value", [7, ["s"], {"value": "s"}, b"s"])
    def test_a_value_that_is_no_string_is_handed_on_for_its_type_to_refuse(self, value: object) -> None:
        """This rule decides presence. What a stated secret may be is the field's own type to decide."""
        assert stated_client_secret(value) is value

    @pytest.mark.parametrize("held", [7, ["s"], {"value": "s"}])
    def test_a_wrapper_holding_no_string_is_unwrapped_for_its_type_to_refuse(self, held: object) -> None:
        """A type that trusts the wrapper never sees the value it has to refuse."""
        assert stated_client_secret(SecretStr(held)) is held  # ty: ignore[invalid-argument-type]
