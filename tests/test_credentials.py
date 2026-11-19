"""The rule that decides how a credential may arrive refuses one supplied as plain text.

A credential bound to a parameter or to a validated mapping is a frame local for the whole call, and
an error reporter that reads frame locals off a traceback records it. Wrapping it is the only thing
that keeps it out, so a value that arrives unwrapped is refused rather than wrapped on the caller's
behalf.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from apron_auth._credentials import arrives_wrapped
from apron_auth.models import SecretToken

# A credential distinctive enough that finding it in a value cannot be a coincidence.
CREDENTIAL = "s3cr3t-credential"  # pragma: allowlist secret


class TestWrappedCredential:
    @pytest.mark.parametrize("wrapper", [SecretStr, SecretToken])
    def test_a_wrapped_credential_is_handed_back_as_the_wrapper(self, wrapper: type[SecretStr]) -> None:
        """The wrapper states nothing as text, so handing it back states nothing to its caller."""
        credential = wrapper(CREDENTIAL)
        assert arrives_wrapped(SecretToken)(credential) is credential

    @pytest.mark.parametrize("wrapper", [SecretStr, SecretToken])
    def test_a_credential_supplied_as_plain_text_is_refused(self, wrapper: type[SecretStr]) -> None:
        with pytest.raises(ValueError, match="wrapped") as caught:
            arrives_wrapped(wrapper)(CREDENTIAL)

        assert CREDENTIAL not in str(caught.value)

    @pytest.mark.parametrize("wrapper", [SecretStr, SecretToken])
    def test_the_refusal_names_the_wrapper_the_field_takes(self, wrapper: type[SecretStr]) -> None:
        """A refusal naming a wrapper the field then refuses sends the caller to a second refusal."""
        with pytest.raises(ValueError) as caught:
            arrives_wrapped(wrapper)(CREDENTIAL)

        assert wrapper.__name__ in str(caught.value)

    @pytest.mark.parametrize("value", ["", "   ", "\t\n"])
    def test_a_blank_string_is_refused_like_any_other(self, value: str) -> None:
        """One rule, so a field refuses every string and a reader has one answer to remember.

        A client secret stating nothing still reads as absent, because the rule that decides what a
        secret states runs before this one and hands it on as absence rather than as a string.
        """
        with pytest.raises(ValueError, match="wrapped"):
            arrives_wrapped(SecretToken)(value)

    def test_absence_is_handed_back(self) -> None:
        assert arrives_wrapped(SecretToken)(None) is None

    @pytest.mark.parametrize("value", [7, ["s"], {"value": "s"}, b"s"])
    def test_a_value_that_is_no_string_is_handed_on_for_its_type_to_refuse(self, value: object) -> None:
        """This rule decides how a credential arrives. What one may be is the field's own type to decide."""
        assert arrives_wrapped(SecretToken)(value) is value
