"""
Local state for managed services.

Managed services (database, storage, cache) need credentials that stay stable
across `perch apply` runs -- if the password regenerated every deploy, every
dependent workload would break. Perch generates each secret once and persists it
in `.perch/state.json` (mode 0600, git-ignored).

This is deliberately a flat file: Perch is single-host by default, so there's no
control-plane database to keep. Back it up alongside your manifest; losing it
means rotating every managed credential.

Sealing (C4): when a master key is configured ($PERCH_MASTER_KEY or
.perch/master.key), the on-disk file is envelope-encrypted as a whole, so copying
it yields ciphertext, not keys. In memory `_data` is always plaintext; only the
disk representation is sealed. With no key configured, the file stays cleartext
JSON exactly as before. Losing the key after sealing is unrecoverable, so loading
a sealed file without the key fails loudly instead of silently discarding state.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path

from . import crypto

_AUTO = object()   # sentinel: auto-detect a sealer from the environment / key file


class State:
    def __init__(self, root: str = ".perch", sealer=_AUTO):
        self.path = Path(root) / "state.json"
        # sealer: a crypto.Sealer, None (force cleartext), or _AUTO (detect a key)
        self._sealer = crypto.default_sealer(root) if sealer is _AUTO else sealer
        self._data: dict = {}
        if self.path.exists():
            self._data = self._load()

    def _load(self) -> dict:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return {}                         # no state yet -> start empty
        except OSError as e:
            # The file exists (caller checked) but can't be read -- a transient
            # EIO/ESTALE/EACCES. Refuse rather than treat as empty, which would
            # let the next flush overwrite real state with {}.
            raise crypto.SealError(
                f"{self.path} exists but could not be read ({e}); refusing to "
                f"continue so existing state is not overwritten") from e
        stripped = raw.strip()
        if crypto.is_sealed(stripped):
            if self._sealer is None:
                raise crypto.SealError(
                    f"{self.path} is sealed but no key is configured -- set "
                    f"${crypto.MASTER_KEY_ENV} or restore .perch/master.key")
            return json.loads(self._sealer.unseal_str(stripped))
        if not stripped:
            return {}                         # genuinely empty file -> empty state
        try:
            return json.loads(raw)            # cleartext (no key) or legacy state
        except json.JSONDecodeError as e:
            # Non-empty but unparseable: corruption or a half-written file. Fail
            # loud instead of silently discarding (and then overwriting) state.
            raise crypto.SealError(
                f"{self.path} is present but not valid JSON ({e}); refusing to "
                f"overwrite existing state -- back it up and inspect it") from e

    def secret(self, project: str, service: str, key: str, nbytes: int = 24) -> str:
        """Return a stable generated secret, creating it on first use."""
        slot = f"{project}/{service}/{key}"
        if slot not in self._data:
            self._data[slot] = secrets.token_urlsafe(nbytes)
            self._flush()
        return self._data[slot]

    def get(self, key: str, default=None):
        """Read a structured value (e.g. the broker issuer key, identity records).
        Stored under reserved top-level keys, distinct from secret() slots."""
        return self._data.get(key, default)

    def put(self, key: str, value) -> None:
        """Persist a structured value, flushing to disk."""
        self._data[key] = value
        self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._data, indent=2, sort_keys=True)
        if self._sealer is not None:          # seal the whole file: ciphertext at rest
            payload = self._sealer.seal(payload)
        # Unique per-write temp file (mkstemp is 0600 on POSIX from creation, so
        # there's no world-readable window and no fixed-name collision between
        # concurrent writers), then atomically rename into place.
        fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent), prefix="state.", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(payload)
            os.chmod(tmp, 0o600)              # belt-and-suspenders (also covers odd umasks)
            tmp.replace(self.path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
