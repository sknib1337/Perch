# Perch

Host your own apps and agents — with a real backend — on infrastructure you
operate. You describe what you want to run in one file, run one command, and
Perch builds it, runs it safely, gives it a web address with automatic HTTPS,
and keeps it running. No managed-platform account, no monthly platform bill.

## The idea in 20 seconds

- An **app** is a website or service (a dashboard, a tool, an API).
- An **agent** is a background helper (a Claude-powered assistant, a daily job).
- A **managed service** is a ready-made backend block Perch runs for you — a
  Postgres database, object storage, a cache, an auto-generated API, or auth.
- You list these in one file (`perch.yaml`), run `perch up`, and Perch wires them
  together and brings everything online. You own the box.

---

## Quick start

Plan on about 15 minutes. You need **Docker** installed and running, and
**Python 3.10+**. Perch is a Python tool — there is no `npm install` and nothing
to compile.

**1. Install**
```bash
curl -fsSL https://raw.githubusercontent.com/sknib1337/Perch/main/install.sh | bash
# or, from the repo:  pip install -e .
```

**2. Check everything's ready**
```bash
perch doctor
```
A simple pass/fail checklist; every ✗ comes with the exact fix.

**3. Describe what to run** — edit `perch.yaml`:
```yaml
services:
  - name: db
    type: postgres                 # a database, vector-search ready

  - name: web
    type: webapp
    build: { context: ./your-app }  # the folder with your app (needs a Dockerfile)
    port: 8080                      # the port your app runs on
    route: { host: web.localhost }  # the web address to visit
    bindings: [db]                  # your app gets DATABASE_URL automatically
```

**4. Turn it on**
```bash
perch up
```
Perch builds your app, starts the database, hands your app its connection
details, and brings everything online — then prints the link.

**5. (Optional) Put it on the internet** — get a small always-on server (about
$5/month), point your domain's A record at it, set `route.host` to your domain,
and run `perch up`. The built-in proxy fetches a secure HTTPS certificate
automatically, and your site is live.

To watch everything in a dashboard, run `perch serve` and open
`http://127.0.0.1:8787`.

---

## What you can run

**Workloads**
- **Apps** (`type: webapp`) — long-running services that receive traffic, routed
  with automatic HTTPS.
- **Agents** (`type: agent`) — background workers; continuous, or on a cron
  schedule via the built-in scheduler.
- **Functions** (`type: function`) — build and run your own handler code with
  per-function secrets and logs.

**Managed backend services** — provisioned from hardened official images, with
generated credentials injected into the workloads that use them:
- **`postgres`** — Postgres with vector search (pgvector), persistent storage,
  generated credentials, and scheduled backups.
- **`cache`** — Redis with append-only persistence.
- **`storage`** — S3-compatible object storage (MinIO) with bucket provisioning.
- **`rest-api`** — an auto-generated REST API (PostgREST) over a `postgres` service.
- **`auth`** — identity (Zitadel): OIDC/OAuth, users, and sessions.

Workloads reference services under `bindings`, and Perch injects the connection
environment automatically (`DATABASE_URL`, `REDIS_URL`, `S3_*`, and so on).

---

## The manifest

One `perch.yaml` is the single source of truth for everything you run.

```yaml
project: my-stack

defaults:
  restart: unless-stopped
  resources: { memory: 512m, cpus: "1.0" }

prune: false        # true: remove managed containers not present in this file

services:
  - name: db
    type: postgres
    version: "16"
    extensions: [pgvector]
    backup: { schedule: "0 2 * * *", retain: 7 }

  - name: web
    type: webapp
    build: { context: ./web }       # local path or Git URL
    port: 8080
    route: { host: app.example.com }
    health: { path: /healthz }
    bindings: [db]
    env:
      - { key: LOG_LEVEL, value: info }
      - { key: API_KEY, value: "${API_KEY}", secret: true }

  - name: report-agent
    type: agent
    build: { context: https://github.com/sknib1337/report-agent }
    schedule: "0 */6 * * *"         # omit for a continuous worker
    bindings: [db]
    env:
      - { key: API_TOKEN, value: "${API_TOKEN}", secret: true }
```

Secrets are `${ENV_VAR}` references resolved when you deploy — never stored in the
file. Managed-service credentials are generated once and kept in git-ignored local
state (`.perch/state.json`).

---

## Web console

`perch serve` runs a single-page command center at `http://127.0.0.1:8787`:

- **Topology** — the dependency graph: workloads perched on managed services,
  edges are bindings, node rings show health.
- **Services / detail** — status, health, config (secrets masked), bindings and
  exports (masked), and live logs.
- **Deploy** — the reconcile plan as a color-coded diff, with one-click apply.
- **Drift** — divergence between the manifest and what's running.
- **Backups** — per-database dumps, with on-demand backup.

The API binds to localhost and is unauthenticated — put it behind the proxy with
auth (or an SSH tunnel) before any remote use. All responses mask secret values
and managed-service credentials.

---

## Operations

| Command | Function |
|---|---|
| `perch doctor` | Validate Docker, Python, and port prerequisites. |
| `perch up` | Initialize if needed, then reconcile and expose. |
| `perch init` | Write a starter `perch.yaml`. |
| `perch plan` | Show the diff between manifest and what's running. No changes applied. |
| `perch apply [--rebuild]` | Reconcile: build changed sources, recreate changed configs, restart stopped services. |
| `perch status` | List services and health. |
| `perch logs <service> [-f]` | Stream service logs. |
| `perch drift` | Read-only posture report (non-zero exit on drift). |
| `perch run <service>` | Execute a one-shot run of a service. |
| `perch proxy` | Generate the Caddy config and run the reverse proxy (automatic TLS). |
| `perch scheduler` | Foreground loop: cron-scheduled agents and managed-service backups. |
| `perch backup [service]` | Dump managed Postgres services (retention applied). |
| `perch restore <service> <file>` | Restore a Postgres service from a dump. |
| `perch serve` | Run the web console + API. |
| `perch destroy` | Remove all managed containers for the project. |

### How it stays in sync

Perch tracks what it owns with container labels and two hashes: a **source hash**
(build identity, plus a content fingerprint of a local build context, so source
changes rebuild) and a **config hash** (env, ports, routing, security, schedule —
a change recreates the container; no change is a no-op). `perch drift` reports
anything missing, stale, stopped, unhealthy, or running outside the manifest.

---

## Security

- Every container runs with safe defaults: non-root, read-only root filesystem,
  all Linux capabilities dropped, `no-new-privileges`, and memory/CPU limits.
  Relaxations are explicit and show up in change review.
- Secrets are referenced from the environment, never committed, and written to a
  `0600` env file at launch so values don't appear in process listings.
- TLS certificates for routed hostnames are issued and renewed automatically.

---

## Words you'll meet

| Word | What it means |
|---|---|
| App / agent | A website/service, or a background helper. |
| Managed service | A ready-made backend block Perch runs for you — a database, storage, a cache, an API, or auth. |
| Manifest (`perch.yaml`) | The one file where you list everything you want running. |
| Bindings | "This app uses that database" — Perch wires the connection in automatically. |
| Secret | A password or API key. You keep it in your environment; it never goes in the file. |
| Proxy | The piece that gives your site a web address and automatic HTTPS. |
| Drift | A check for anything that no longer matches your file. |

---

## If something breaks

Run this first — it explains most problems in plain words:
```bash
perch doctor
```

| What you see | What it means | What to do |
|---|---|---|
| "Docker isn't ready" | Docker isn't running | Open Docker Desktop and wait for it to start |
| "Port 80 is in use" | Something else is on the web port | Close the other program, or skip `perch proxy` for now |
| "missing secret: …" | A password/key isn't set | Run `export NAME=value`, then `perch up` again |
| Page won't load | The `port` doesn't match your app | Set `port` to the number your app shows when it starts |

See `perch status` (what's running), `perch logs <name>` (output), and
`perch destroy` (tear it all down). The deeper deployment and production guide is
in [GETTING_STARTED.md](GETTING_STARTED.md).

---

## Requirements

- Docker Engine (or Docker Desktop), installed and running.
- Python 3.10+.
- Ports 80/443 available if you use the built-in proxy.

## Extending it

The reconciler is backend-agnostic. Docker is the shipped implementation; the
`Backend` protocol in `perch/backend.py` can target Compose, Nomad, a remote host
over SSH, or another runtime without changing reconciliation logic.

## Repository layout

```
perch/
  manifest.py        schema, defaults, secret resolution, hashing, dependency order
  backend.py         backend interface + observed-state + managed-spec types
  docker_backend.py  default backend: build/spec + hardened runtime, exec, dumps
  catalog.py         managed-service catalog (postgres, cache, storage, rest-api, auth)
  state.py           generated managed-service credentials (.perch/state.json)
  backups.py         backup layout + retention
  api.py             HTTP API for the web console (stdlib; secrets masked)
  web/index.html     single-page command center
  reconcile.py       backend-agnostic plan / apply / drift, bindings + ordering
  proxy.py           Caddy configuration generation
  cli.py             operator commands + scheduler + serve
install.sh           prerequisite-checking installer
examples/hello-web/  reference application
design/              console design source
tests/               offline tests (no Docker required)
.github/workflows/   CI (runs the test suite on 3.10-3.12)
```

## License

Apache-2.0.
