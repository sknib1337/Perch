"""
C10 -- agent memory integrity & provenance.

Agents accumulate memory/state, and poisoned or tampered memory steers future
behavior. This is a tamper-evident, append-only log so that modification,
reordering, insertion, deletion, or truncation of an agent's memory is detectable.

Two layers:
  - Hash chain (provenance + integrity): each record commits to the previous
    record's hash, so editing, reordering, or inserting any record breaks the
    chain. `verify()` recomputes it from genesis. This catches accidental
    corruption and an attacker who edits records without rebuilding the chain.
  - MAC anchor (tamper-evidence vs. an active attacker): the head (length + head
    hash) is sealed with a key Perch holds, not the agent. An attacker who
    rebuilds a *consistent* alternate chain, or truncates trailing records, still
    can't reproduce the anchor without the key. Perch notarizes the head
    periodically; each anchor is a checkpoint history can't be rewritten before.

The hash/HMAC use only the stdlib. The anchor key lives in sealed state (C4); a
natural producer of these records is the C9 mediation audit log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

GENESIS = "0" * 64
_RECORD_CTX = b"perch-memory-v1"
_ANCHOR_CTX = b"perch-memory-anchor-v1"
_MIN_KEY_BYTES = 16


def _check_canonical(value) -> None:
    """Reject inputs that don't serialize to one canonical form, so the hash is
    injective: non-string dict keys (which JSON would coerce to strings, letting
    {1:..} and {'1':..} collide) and NaN/Inf (non-standard JSON) fail loudly."""
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"memory dict keys must be strings, got {type(k).__name__}")
            _check_canonical(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check_canonical(v)


def _record_hash(seq: int, prev_hash: str, data) -> str:
    _check_canonical(data)
    payload = json.dumps({"seq": seq, "prev": prev_hash, "data": data},
                         sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(_RECORD_CTX + b"\x00" + payload).hexdigest()


@dataclass
class Record:
    seq: int
    prev_hash: str
    data: object
    hash: str

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Record":
        return Record(int(d["seq"]), d["prev_hash"], d["data"], d["hash"])


class MemoryLog:
    """An append-only, hash-chained log of memory records."""

    def __init__(self, records=None):
        self._records: list[Record] = list(records or [])

    def append(self, data) -> Record:
        seq = len(self._records)
        prev = self._records[-1].hash if self._records else GENESIS
        rec = Record(seq, prev, data, _record_hash(seq, prev, data))
        self._records.append(rec)
        return rec

    def records(self) -> list:
        return list(self._records)

    def head(self) -> str:
        return self._records[-1].hash if self._records else GENESIS

    def verify(self) -> bool:
        """True iff the hash chain is intact: each record is at its position,
        links the previous head, and its hash matches its contents."""
        prev = GENESIS
        for i, r in enumerate(self._records):
            if r.seq != i or r.prev_hash != prev:
                return False
            if r.hash != _record_hash(r.seq, r.prev_hash, r.data):
                return False
            prev = r.hash
        return True

    # ---- MAC anchor (tamper-evidence vs. an attacker without the key) -----
    def anchor(self, key: bytes) -> str:
        """A MAC over (length, head) -- the notarized checkpoint. Binding the
        length makes truncation detectable; the head binds all content."""
        if len(key) < _MIN_KEY_BYTES:
            raise ValueError("anchor key too short")
        msg = f"{len(self._records)}:{self.head()}".encode()
        return hmac.new(key, _ANCHOR_CTX + b"\x00" + msg, hashlib.sha256).hexdigest()

    def verify_against(self, key: bytes, anchor: str) -> bool:
        """True iff the chain is intact AND matches a previously taken anchor.
        Catches truncation and whole-chain rewrites that `verify()` alone can't."""
        return self.verify() and hmac.compare_digest(self.anchor(key), str(anchor))

    def to_dict(self) -> dict:
        return {"records": [r.to_dict() for r in self._records]}

    @staticmethod
    def from_dict(d: dict) -> "MemoryLog":
        return MemoryLog([Record.from_dict(r) for r in (d or {}).get("records", [])])
