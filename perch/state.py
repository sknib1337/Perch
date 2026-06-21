"""
Local state for managed services.

Managed services (database, storage, cache) need credentials that stay stable
across `perch apply` runs -- if the password regenerated every deploy, every
dependent workload would break. Perch generates each secret once and persists it
in `.perch/state.json` (mode 0600, git-ignored).

This is deliberately a flat file: Perch is single-host by default, so there's no
control-plane database to keep. Back it up alongside your manifest; losing it
means rotating every managed credential.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path


class State:
    def __init__(self, root: str = ".perch"):
        self.path = Path(root) / "state.json"
        self._data: dict = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def secret(self, project: str, service: str, key: str, nbytes: int = 24) -> str:
        """Return a stable generated secret, creating it on first use."""
        slot = f"{project}/{service}/{key}"
        if slot not in self._data:
            self._data[slot] = secrets.token_urlsafe(nbytes)
            self._flush()
        return self._data[slot]

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
