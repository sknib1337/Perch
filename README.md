# Perch

A secure-by-default runtime for self-hosted apps and **AI agents**. You describe
what you want to run in one file, run one command, and Perch builds it, runs it
under hardened defaults, gives it a web address with automatic HTTPS, and keeps it
running — on infrastructure you operate. No managed-platform account, no monthly
platform bill.

Agents are treated as a distinct risk: a single workload can be given its own
short-lived, least-privilege identity and hold no long-lived secrets. The identity
controls are opt-in and fully backwards compatible — off by default, and an
existing `perch.yaml` runs byte-for-byte as before. When enabled, a workload gets a
per-run cryptographic identity, a credential broker that issues scoped, short-TTL
database credentials in place of a permanent `DATABASE_URL`, attestation before
issuance, controlled egress, envelope-encrypted state at rest, and an authenticated
control-plane API. The full design and what each control does (and does not) cover
is in [THREAT_MODEL.md](THREAT_MODEL.md).

## The idea in 20 seconds

- An **app** is a website or service (a dashboard, a tool, an API).
- An **agent** is a background helper (a Claude-powered assistant, a daily job).
- A **managed service** is a ready-made backend block Perch runs for you — a
  Postgres database, object storage, a cache, an auto-generated API, or auth.
- **Secure by default**: containers run non-root with dropped capabilities, and an
  agent can be given a short-lived, least-privilege identity instead of a permanent
  secret (opt-in; see [Securing agents](#securing-agents-opt-in)).
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
# optional asymmetric crypto (Ed25519 identities + Fernet-sealed state):
#                     pip install -e ".[crypto]"
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

## Securing agents (opt-in)

Everything above runs an agent the simple way: a static, long-lived `DATABASE_URL`
and full outbound internet. That's fine for trusted code. When the workload is an
**AI agent** — code you don't fully control, reacting to untrusted input — you can
tighten it without changing the agent itself. Each control below is a few lines of
manifest, off unless you set it, and maps to a numbered control in
[THREAT_MODEL.md](THREAT_MODEL.md).

```yaml
  - name: assistant
    type: agent
    build: { context: ./assistant }
    bindings: [db, cache]

    identity:                       # C1/C2 — per-run, scoped, short-TTL credentials
      ttl: 900                      #   instead of a permanent DATABASE_URL password
      scopes: { db: read }          #   least privilege per binding (default: write)

    egress: { allow: [api.anthropic.com] }   # C8 — default-deny outbound; only these hosts

    mcp:                            # C9 — default-deny tool/MCP mediation (enforced by a gateway)
      servers: { github: https://mcp.example.com/github }
      allow: { tools: ["github.*"] }          #   only these tools reach the upstream server

    verify:                         # C12 — supply-chain integrity
      pin: true                     #   image must be pinned to a @sha256 digest
      registries: [ghcr.io, docker.io]        #   and pulled only from these registries
```

What each one does:

- **`identity`** — instead of injecting a permanent database password, Perch's
  broker issues a fresh, scoped, short-TTL credential per run. The agent holds no
  long-lived secret; the credential expires on its own (`ttl`, capped at one hour),
  and `scopes` narrows each binding to `read` or `write` (default `write`, so
  enabling identity never silently breaks an existing writer). Issuance is gated by
  **attestation** (C3): the running config and build identity must match what's
  expected before any credential is minted.
- **`egress`** — `deny` removes the workload's route off-box (it is placed on an
  internal Docker network with no route to the internet); `{allow: [...]}` permits
  only the listed hosts through a default-deny forward proxy. Bound managed services
  stay reachable. (Docker's embedded DNS resolver can still forward lookups upstream,
  so DNS is not a sealed channel — see [THREAT_MODEL.md](THREAT_MODEL.md) C8.) Omit
  the field for today's full outbound internet.
- **`mcp`** — points the agent's MCP client at a per-agent **mediating gateway** that
  authorizes every tool/resource/prompt call against a default-deny allowlist and
  forwards only what's allowed to the `servers` you list (HTTP or local stdio).
  `*/list` responses are filtered to the allowlist (the model never sees a disallowed
  capability), and server-initiated `sampling`/`completion` are denied unless enabled.
  With `egress` set, the gateway is the agent's only outbound path, so it can't be
  bypassed; denied calls feed the same audit/quarantine loop as the broker.
- **`verify`** — refuses to run an image unless it is pinned to an immutable
  `@sha256:` digest (a mutable `:latest` can change under you between pull and run)
  and, optionally, pulled only from allow-listed registries. A malformed digest
  fails closed rather than being treated as unpinned.

Two host-level settings back these up:

- **Sealed state at rest (C4)** — set `PERCH_MASTER_KEY` (or drop a key at
  `.perch/master.key`) and `.perch/state.json` is envelope-encrypted as a whole, so
  a stolen copy or backup yields ciphertext, not credentials. In memory it's always
  plaintext; only the disk file is sealed. Loading a sealed file with no key fails
  loudly rather than discarding state.
- **Authenticated control plane (C7)** — `perch serve --require-auth` gates the
  console API behind bearer tokens with viewer/admin roles (writes require `admin`).

**Crypto backend.** The defaults use only the standard library: HMAC-SHA256 for
identities, an HKDF + encrypt-then-MAC scheme for sealed state. Install the optional
extra (`pip install -e ".[crypto]"`) and Perch automatically upgrades to **Ed25519**
identities (the broker verifies with a public key it cannot forge) and **Fernet**
for sealed state — no config change. `PERCH_CRYPTO_BACKEND=stdlib` forces the
stdlib path even when the extra is present. The optional dependency is never
required; stdlib is the baseline.

When `identity` is enabled, every issuance, denial, and attestation result is
written to a tamper-evident audit log (hash chain + keyed anchor); repeated denials
trip an anomaly threshold that can quarantine a subject and revoke its tickets
(C10/C11). Residual gaps for every control are documented honestly in
[THREAT_MODEL.md](THREAT_MODEL.md) — they are not hidden.

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

By default the API binds to localhost and is **unauthenticated** — put it behind the
proxy with auth (or an SSH tunnel) before any remote use. To require credentials,
run `perch serve --require-auth`: requests to `/api/` then need a bearer token
(`PERCH_API_TOKENS` or `.perch/api_tokens.json`; a one-time admin token is printed
if none are configured) and writes require the `admin` role. All responses mask
secret values and managed-service credentials either way.

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
| `perch serve [--require-auth]` | Run the web console + API (optionally token-gated). |
| `perch destroy` | Remove all managed containers for the project. |

### How it stays in sync

Perch tracks what it owns with container labels and two hashes: a **source hash**
(build identity, plus a content fingerprint of a local build context, so source
changes rebuild) and a **config hash** (env, ports, routing, security, schedule —
a change recreates the container; no change is a no-op). The opt-in security fields
are mixed into the config hash only when set, so enabling one is a real change while
existing manifests hash exactly as before. `perch drift` reports anything missing,
stale, stopped, unhealthy, or running outside the manifest.

---

## Security

**Baseline — always on, for every workload:**

- Containers run with safe defaults: non-root, read-only root filesystem, all Linux
  capabilities dropped, `no-new-privileges`, and memory/CPU limits. Relaxations are
  explicit and show up in change review.
- Secrets are referenced from the environment, never committed, and written to a
  `0600` env file at launch so values don't appear in process listings.
- Local state (`.perch/state.json`) is written `0600` via an atomic replace.
- TLS certificates for routed hostnames are issued and renewed automatically.

**Opt-in — per-agent hardening:** per-run scoped identities, attestation, controlled
egress, tool/MCP mediation, supply-chain pinning, sealed state, and an authenticated
console. See [Securing agents](#securing-agents-opt-in) and
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## Words you'll meet

| Word | What it means |
|---|---|
| App / agent | A website/service, or a background helper. |
| Managed service | A ready-made backend block Perch runs for you — a database, storage, a cache, an API, or auth. |
| Manifest (`perch.yaml`) | The one file where you list everything you want running. |
| Bindings | "This app uses that database" — Perch wires the connection in automatically. |
| Secret | A password or API key. You keep it in your environment; it never goes in the file. |
| Identity | An opt-in, short-lived, least-privilege credential Perch mints per run, instead of a permanent password. |
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
| "sealed but no key is configured" | `.perch/state.json` was sealed and the key is missing | Restore `.perch/master.key` or set `PERCH_MASTER_KEY` |

See `perch status` (what's running), `perch logs <name>` (output), and
`perch destroy` (tear it all down). The deeper deployment and production guide is
in [GETTING_STARTED.md](GETTING_STARTED.md).

---

## Requirements

- Docker Engine (or Docker Desktop), installed and running.
- Python 3.10+.
- Ports 80/443 available if you use the built-in proxy.
- Optional: the `crypto` extra (`cryptography>=42`) for Ed25519 identities and
  Fernet-sealed state. Never required — stdlib is the default.

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
  state.py           generated managed-service credentials (.perch/state.json), sealing
  backups.py         backup layout + retention
  api.py             HTTP API for the web console (stdlib; secrets masked; token auth)
  web/index.html     single-page command center
  reconcile.py       backend-agnostic plan / apply / drift, bindings + ordering
  proxy.py           Caddy configuration generation
  cli.py             operator commands + scheduler + serve
  # --- secure-by-default agent runtime (opt-in; see THREAT_MODEL.md) ---
  identity.py        C2  per-agent cryptographic identity (HMAC -> Ed25519)
  broker.py          C1  short-lived, scoped credential broker
  attest.py          C3  attestation of config + build identity before issuance
  crypto.py          C4  sealed state (HKDF encrypt-then-MAC -> Fernet)
  dataplane.py       C5/C6 identity-aware per-run datastore credentials + scopes
  egress.py          C8  egress policy + network segmentation
  mediation.py       C9  MCP / tool-call mediation policy (tools/resources/prompts)
  mcp.py             C9  MCP protocol decision core (JSON-RPC, per-method mediation)
  gateway.py         C9  per-agent mediating gateway sidecar (runtime enforcement)
  memory.py          C10 tamper-evident agent memory log
  audit.py           C11 audit log, anomaly detection, quarantine
  supplychain.py     C12 image digest pinning + registry allow-list
install.sh           prerequisite-checking installer
THREAT_MODEL.md      controls C1-C12, trust boundaries, adversaries, residuals
examples/hello-web/  reference application
design/              console design source
tests/               offline tests (no Docker required)
.github/workflows/   CI (runs the test suite on 3.10-3.12)
```

## License

Apache-2.0.
