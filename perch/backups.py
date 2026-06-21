"""
Backup bookkeeping for managed data services.

Dumps land under .perch/backups/<project>/<service>/<timestamp>.sql.gz. The
actual dump/restore is the backend's job (it knows how to reach the container);
this module owns the layout and retention policy so they can be tested without
a running database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def backup_dir(root: str, project: str, service: str) -> Path:
    return Path(root) / "backups" / project / service


def new_backup_path(root: str, project: str, service: str, now: datetime | None = None) -> Path:
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    return backup_dir(root, project, service) / f"{stamp}.sql.gz"


def prune(root: str, project: str, service: str, retain: int) -> list[Path]:
    """Delete all but the `retain` most recent dumps. Returns the kept files."""
    d = backup_dir(root, project, service)
    if not d.exists():
        return []
    dumps = sorted(d.glob("*.sql.gz"))          # timestamped names sort chronologically
    keep = dumps[-retain:] if retain > 0 else dumps
    for old in dumps[:-retain] if retain > 0 else []:
        old.unlink(missing_ok=True)
    return keep
