# Changelog

## 0.3.0
- **Secure-by-default agent runtime (opt-in; controls C1–C12).** A workload can be
  given its own short-lived, least-privilege identity and hold no long-lived secrets.
  Per-run cryptographic identity (`identity.py`) and a scoped, short-TTL credential
  broker (`broker.py`) that issues per-run datastore credentials in place of a static
  `DATABASE_URL` (`dataplane.py`), gated by attestation (`attest.py`); default-deny
  egress with network segmentation (`egress.py`); a per-agent **MCP / tool-call
  mediation gateway** that authorizes every call against a default-deny allowlist,
  requires a per-agent bearer token, and feeds a tamper-evident audit + quarantine
  loop (`mediation.py` / `mcp.py` / `gateway.py`, `audit.py`, `memory.py`);
  envelope-encrypted state at rest (`crypto.py` / `state.py`); an authenticated
  control-plane API (`perch serve --require-auth`); and supply-chain image pinning
  (`supplychain.py`). All opt-in and backwards compatible — an existing `perch.yaml`
  is unaffected. Hybrid crypto: stdlib by default, Ed25519 + Fernet with the optional
  `crypto` extra. Design, trust boundaries, and residuals are in `THREAT_MODEL.md`.
- **`perch validate`** — daemon-free structural check of a manifest (parse, types,
  bindings, references, policy compilation); CI-friendly, exits non-zero on problems.
- **Worked example** (`examples/secure-agent/`) — one agent under identity + egress +
  MCP mediation, with a runnable demo assistant.
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
