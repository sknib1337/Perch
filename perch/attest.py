"""
C3 -- attestation before issuance.

The broker (C1) will not mint a credential for an instance it cannot attest. An
attestation answers "is the thing asking actually the workload it claims to be,
running what we expect?" -- and any mismatch denies, closed.

It reuses the machinery Perch already has for drift detection: a workload's
`source_hash` (build/image identity, mixed with a local content fingerprint) and
`config_hash` (env/ports/security/route/...), plus the deterministic container
host name `perch-<project>-<service>`. An `Expectation` is what Perch derives from
the manifest for a subject; an `Attestation` is what the requesting instance
presents. They must match on every field.

Phase A note: the strongest binding -- a cryptographic image *digest* and signed
provenance -- is C12 (supply chain). Here `source_hash` stands in as the artifact
identity; the `Attestor` interface is unchanged when C12 swaps in a digest.

Seam for later phases: a live broker (C5) will receive an `Attestation` from a
remote instance over the wire; the comparison logic is identical, only the source
of the presented values changes.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class Attestation:
    """What a requesting instance presents about itself."""
    subject: str
    source_hash: str
    config_hash: str
    host: str


@dataclass(frozen=True)
class Expectation:
    """What Perch expects for a subject, derived from the manifest."""
    subject: str
    source_hash: str
    config_hash: str
    host: str


def _eq(a: str, b: str) -> bool:
    # Constant-time compare; the values aren't secret, but it's free hygiene and
    # keeps the matcher uniform with the rest of the identity spine. Compare on
    # encoded bytes so a non-ASCII name can't make compare_digest raise.
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


class Attestor:
    """Holds the expected instance for each subject and verifies attestations
    against it. Unknown subject or any field mismatch -> False (fail closed)."""

    def __init__(self, expectations: "list[Expectation] | None" = None):
        self._by_subject: dict[str, Expectation] = {
            e.subject: e for e in (expectations or [])}

    def expect(self, expectation: Expectation) -> None:
        self._by_subject[expectation.subject] = expectation

    def expectation_for(self, subject: str) -> "Expectation | None":
        return self._by_subject.get(subject)

    def __contains__(self, subject: str) -> bool:
        return subject in self._by_subject

    def verify(self, attestation: Attestation) -> bool:
        """True iff `attestation` matches the registered expectation for its
        subject on image/source identity, config, and host."""
        exp = self._by_subject.get(attestation.subject)
        if exp is None:
            return False
        return (_eq(attestation.source_hash, exp.source_hash)
                and _eq(attestation.config_hash, exp.config_hash)
                and _eq(attestation.host, exp.host))
