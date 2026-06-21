# Changelog

## 0.3.0
- **Web console + API.** New `perch serve` runs an HTTP API (`perch/api.py`) and a
  single-page command center (`perch/web/index.html`) built from the design
  system. Screens: Topology, Services, Service detail, Deploy (plan/apply), Drift,
  Backups, Manifest. All secrets and managed-service credentials are masked.
- **Authentication service** (`type: auth`, Zitadel) wired to a `postgres` service.
- **Functions** (`type: function`) — build + run user code with bindings, secrets, logs.
- **Packaging:** single-sourced version from `perch.__version__`; automated PyPI publishing via GitHub Actions Trusted Publishing (see `RELEASING.md`).

## 0.2.0
- **Managed backend services**: `postgres` (pgvector), `cache` (Redis),
  `storage` (MinIO), `rest-api` (PostgREST).
- **Bindings** auto-inject connection env; dependency-ordered convergence.
- **Backups**: `perch backup` / `perch restore`, retention, scheduled dumps.
- Generated credentials persisted in git-ignored `.perch/state.json`.

## 0.1.0
- Initial release: declarative app/agent orchestration on Docker, hardened
  containers, Caddy TLS proxy, drift detection, cron scheduler.
