"""
C11 -- detection: tamper-evident audit + anomaly response.

The identity spine produces exactly the signals worth watching: who was issued a
credential, who was denied, whose attestation or identity proof failed. This
records those events in a tamper-evident log (the C10 hash chain + MAC anchor, so
an attacker can't quietly erase their tracks), detects anomalies over them, and
feeds an automated response -- quarantine -- that the broker honors on the next
request.

  - `AuditLog`   -- append security events to a tamper-evident `MemoryLog`.
  - `Detector`   -- threshold rules over the events -> `Anomaly` list.
  - `Quarantine` -- subjects to refuse; the broker (C1) checks it before issuing.

The loop: broker emits events -> Detector scans -> flagged subjects are quarantined
-> broker denies them, closed. All pure/offline-testable; persistence rides on the
sealed state (C4).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .memory import MemoryLog

# Event kinds (the security-relevant signals from the identity spine).
ISSUE = "credential.issue"
DENY = "credential.deny"            # out-of-scope / quarantined
ATTEST_FAIL = "attestation.fail"
VERIFY_FAIL = "identity.verify_fail"


class AuditLog:
    """A tamper-evident, append-only record of security events."""

    def __init__(self, log: "MemoryLog | None" = None):
        self._log = log or MemoryLog()

    def record(self, kind: str, subject: str, detail: str = "", at: int = 0) -> None:
        self._log.append({"kind": kind, "subject": subject, "detail": str(detail), "at": int(at)})

    def events(self) -> list:
        return [r.data for r in self._log.records()]

    def truncated(self, keep: int) -> "AuditLog":
        """A fresh log of just the most recent `keep` events (re-chained, so still
        verifiable/anchorable), bounding state growth. Older events drop out of
        the tamper-evident window -- anchor periodically if you need them."""
        events = self.events()
        if len(events) <= keep:
            return self
        fresh = MemoryLog()
        for e in events[-keep:]:
            fresh.append(e)
        return AuditLog(fresh)

    def anchor(self, key: bytes) -> str:
        return self._log.anchor(key)

    def verify_against(self, key: bytes, anchor: str) -> bool:
        return self._log.verify_against(key, anchor)

    def to_dict(self) -> dict:
        return self._log.to_dict()

    @staticmethod
    def from_dict(d: dict) -> "AuditLog":
        return AuditLog(MemoryLog.from_dict(d))


@dataclass
class Anomaly:
    subject: str
    rule: str
    count: int
    detail: str


class Detector:
    """Threshold rules over audit events. Deliberately simple and explainable:
    repeated denials/attestation-failures/verify-failures for a subject are the
    signature of a compromised or misbehaving agent probing the broker."""

    def __init__(self, deny_threshold: int = 5, attest_fail_threshold: int = 3,
                 verify_fail_threshold: int = 3):
        self.deny_threshold = deny_threshold
        self.attest_fail_threshold = attest_fail_threshold
        self.verify_fail_threshold = verify_fail_threshold

    def scan(self, events) -> "list[Anomaly]":
        tally: dict = defaultdict(lambda: defaultdict(int))
        for e in events:
            tally[e.get("subject", "")][e.get("kind", "")] += 1
        out: list[Anomaly] = []
        for subject, kinds in tally.items():
            denials = kinds.get(DENY, 0)         # scope/quarantine denials only; the
            if denials >= self.deny_threshold:   # attest/verify rules below are separate
                out.append(Anomaly(subject, "excessive_denials", denials,
                                   f"{denials} denied/failed requests"))
            if kinds.get(ATTEST_FAIL, 0) >= self.attest_fail_threshold:
                out.append(Anomaly(subject, "repeated_attestation_failure",
                                   kinds[ATTEST_FAIL], "attestation mismatches"))
            if kinds.get(VERIFY_FAIL, 0) >= self.verify_fail_threshold:
                out.append(Anomaly(subject, "repeated_identity_failure",
                                   kinds[VERIFY_FAIL], "identity proof failures"))
        return out


class Quarantine:
    """Subjects the broker must refuse. Automated response to a detected anomaly."""

    def __init__(self, subjects=None):
        self._set = set(subjects or [])

    def add(self, subject: str) -> None:
        self._set.add(subject)

    def remove(self, subject: str) -> None:
        self._set.discard(subject)

    def __contains__(self, subject: str) -> bool:
        return subject in self._set

    def subjects(self) -> list:
        return sorted(self._set)

    def to_dict(self) -> dict:
        return {"subjects": self.subjects()}

    @staticmethod
    def from_dict(d: dict) -> "Quarantine":
        return Quarantine((d or {}).get("subjects", []))
