"""Type-level assertions that a workload verifier takes its issuers as typed values.

Nothing here runs. ``ty`` checks the file, and every ``ty: ignore`` marks a call that must stay a type
error. If a call below starts type-checking, its suppression becomes unused and the check fails, so these
are assertions rather than decoration.
"""

from __future__ import annotations

from apron_auth import WorkloadIssuer
from apron_auth.workload import WorkloadTokenVerifier

issuer = WorkloadIssuer(issuer="https://token.actions.example.com")

verifier = WorkloadTokenVerifier([issuer])


def a_verifier_takes_a_collection_of_issuers() -> None:
    WorkloadTokenVerifier([issuer])
    WorkloadTokenVerifier((issuer,))
    WorkloadTokenVerifier({issuer})


def an_issuer_identifier_is_not_an_issuer() -> None:
    WorkloadTokenVerifier("https://token.actions.example.com")  # ty: ignore[invalid-argument-type]


def a_collection_of_identifiers_is_not_a_collection_of_issuers() -> None:
    WorkloadTokenVerifier(["https://token.actions.example.com"])  # ty: ignore[invalid-argument-type]


def one_issuer_is_not_a_collection() -> None:
    WorkloadTokenVerifier(issuer)  # ty: ignore[invalid-argument-type]


async def an_audience_is_not_positional() -> None:
    await verifier.verify(  # ty: ignore[missing-argument]
        "token",
        "https://gateway.example.com",  # ty: ignore[too-many-positional-arguments]
    )
