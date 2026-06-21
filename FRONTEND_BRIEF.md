# Perch — Frontend Brief

A reference for building a web visualization/console on top of Perch. It covers
what Perch is, the entities a UI renders, the state machines behind them, the
operations a UI triggers, and a proposed read/write API contract (Perch is
CLI-first today; a thin HTTP layer is the missing piece — specced in §6).

---

## 1. What Perch is

Perch is a **self-hosted backend platform and orchestrator**. From a single
declarative manifest (`perch.yaml`), it runs a project's **workloads**
(applications and agents) and **managed backend services** (Postgres, Redis,
object storage, auto-generated REST API) as hardened Docker containers, wires
them together, exposes them over HTTPS, and continuously reconciles the running
state to match the manifest.

Mental model for the UI: a **project** is a tree. **Managed services** are the
branches (data, cache, storage, API); **applications and agents** perch on them
via **bindings**. The console's job is to make that tree, its health, and its
drift from intent legible — and to let an operator act on it.

---

## 2. Domain model

Entities the UI renders and their relationships:

```
Project 1───* Service ──┬── (webapp | agent)         → can have a Route, Health, Schedule
                        └── (postgres|cache|storage|rest-api = managed) → exposes Exports
Service *───* Service     via `bindings`  (workload → managed service)  → Topology edges
Service 1───* Deployment  (observed container state + hashes + health)
Service 1───* LogLine
postgres 1──* Backup
Reconcile → PlanAction[] (the diff) and DriftFinding[] (the posture)
```

### Service (manifest declaration)

The union type the UI edits/displays. Fields vary by `type`.

```json
{
  "name": "web",
  "type": "webapp",                  // webapp | agent | postgres | cache | storage | rest-api
  "build": { "context": "./web", "dockerfile": "Dockerfile", "args": {}, "target": null },
  "image": null,                     // alt to build: a prebuilt image
  "command": null,
  "port": 8080,                      // webapp: listening port
  "route": { "host": "app.example.com", "path": null },
  "health": { "path": "/healthz" },
  "schedule": null,                  // agent: 5-field cron; null = continuous
  "bindings": ["db"],                // managed services to wire in
  "env": [
    { "key": "LOG_LEVEL", "value": "info", "secret": false },
    { "key": "API_KEY",   "value": "${API_KEY}", "secret": true }   // never show resolved value
  ],
  "security": { "read_only_rootfs": true, "no_new_privileges": true,
                "drop_caps": ["ALL"], "add_caps": [], "user": "10001:10001" },
  "resources": { "memory": "512m", "cpus": "1.0" },
  "restart": "unless-stopped",
  "volumes": ["data:/data"],

  // managed-service-only fields:
  "version": "16",                   // postgres
  "extensions": ["pgvector"],        // postgres
  "buckets": ["uploads", "exports"], // storage
  "database": "db",                  // rest-api → references a postgres service
  "backup": { "schedule": "0 2 * * *", "retain": 7 }   // postgres
}
```

`is_managed` is true when `type ∈ {postgres, cache, storage, rest-api}`. Managed
services are **internal-only** (no public route); workloads are routed.

### Deployment / observed state (per service)

What's actually running, used for status badges and drift. (Source: container
labels + inspect.)

```json
{
  "name": "web",
  "status": "running",          // running | exited | created | missing
  "health": "healthy",          // healthy | unhealthy | starting | none
  "image": "perch/my-stack-web:ab12…",
  "source_hash": "ab12…",       // build identity
  "config_hash": "cd34…"        // env/ports/security/etc.
}
```

### Binding exports (what a managed service injects)

For the topology side panel — the connection env a bound workload receives.
**Values are secret; mask them in any API/UI.**

| Service type | Internal port | Injected env keys |
|---|---|---|
| `postgres` | 5432 | `PGHOST` `PGPORT` `PGUSER` `PGPASSWORD` `PGDATABASE` `DATABASE_URL` |
| `cache` | 6379 | `REDIS_URL` |
| `storage` | 9000 (console 9001) | `S3_ENDPOINT` `S3_ACCESS_KEY` `S3_SECRET_KEY` `S3_BUCKETS` |
| `rest-api` | 3000 | `REST_URL` |

Container DNS name (the topology node id): `perch-{project}-{service}`.

### PlanAction (the diff a deploy will perform)

```json
{ "kind": "create", "target": "db", "detail": "postgres (managed)" }
```

### DriftFinding (posture report)

```json
{ "code": "UNHEALTHY", "service": "web", "message": "failing healthcheck" }
```

### Backup (postgres)

```json
{ "service": "db", "file": "20260620T020000Z.sql.gz", "size": 184320,
  "created_at": "2026-06-20T02:00:00Z" }
```

---

## 3. State machines / enums (drive colors, badges, filters)

**Service type** — `webapp | agent | postgres | cache | storage | rest-api`
(suggest two visual groups: *workloads* = webapp/agent, *managed* = the rest).

**Lifecycle status** — `running` (green) · `created` (grey) · `exited` (red) ·
`missing` (declared but no container; amber).

**Health** — `healthy` (green) · `starting` (blue/pulse) · `unhealthy` (red) ·
`none` (no healthcheck configured; neutral).

**Plan action kind** — `create` (+) · `rebuild` (↑, source changed) ·
`reconfigure` (~, config changed) · `restart` (∗, was down) · `prune` (−, not in
manifest) · `noop` (=, up to date). Render as a diff list; `noop` greyed.

**Drift code** — `MISSING` (declared, not running) · `STALE` (older source) ·
`DRIFT` (live config ≠ manifest) · `DOWN` (stopped) · `UNHEALTHY` (failing
healthcheck) · `UNMANAGED` (running, not in manifest). Empty list = "in sync."

---

## 4. Operations → UI actions

Each maps to a CLI command today and to a proposed endpoint in §6.

| UI action | Command | Notes |
|---|---|---|
| Environment readiness banner | `doctor` | Docker/Python/port checks, pass/fail + fix text |
| Deploy / Apply | `apply` (`--rebuild`) | Show `plan` diff first; confirm; stream progress |
| Preview changes | `plan` | Read-only diff; no side effects |
| Service list + health | `status` | Cards/table with status + health badges |
| Live logs | `logs <svc> [-f]` | Stream to a log pane |
| Posture / audit | `drift` | Findings list; non-zero exit drives an alert badge |
| One-shot run | `run <svc>` | Useful for agents; show exit code |
| Expose on URL | `proxy` | Generates Caddy config, runs the reverse proxy (TLS) |
| Scheduler status | `scheduler` | Cron agents + scheduled backups (long-running) |
| Back up DB | `backup [svc]` | pg_dump + retention |
| Restore DB | `restore <svc> <file>` | From a listed backup |
| Tear down | `destroy` | Remove all managed containers for the project |

---

## 5. Suggested screens

1. **Dashboard / Topology** — the tree graph. Nodes = services (icon by type,
   ring color by health). Edges = `bindings` (workload → managed). Badges for
   drift count and unhealthy count. This is the flagship visualization.
2. **Service detail** — tabs: Overview (status/health/image/hashes), Config
   (manifest fields, secrets masked), Bindings/Exports (masked), Logs, and —
   for postgres — Backups.
3. **Deploy** — render `plan` as a color-coded diff (create/rebuild/reconfigure/
   restart/prune/noop), confirm, then stream `apply`.
4. **Drift / Audit** — the findings table; a healthy empty-state when in sync.
5. **Backups** — per-database list with restore and "back up now."
6. **Manifest editor** (optional) — YAML or form view that writes `perch.yaml`,
   then routes to the Deploy screen.

Branding cue: lean on the perch/tree metaphor — managed services as branches,
apps/agents perched on them, edges as the bindings that hold them up.

---

## 6. Data contract (implemented in `perch/api.py`)

The console is backed by a thin read/write HTTP API (Python stdlib only — no
extra dependencies) wrapping `Reconciler.plan()/drift()`,
`DockerBackend.list_managed()/logs()`, `Manifest.load()`,
`catalog.exports_for()`, and the backup helpers, with **all secret values
masked**. It is served alongside the console by `perch serve`. The surface:

```
GET  /api/project                      -> { project, prune }
GET  /api/services                     -> [ Service + observed state + bound_to[] ]
GET  /api/services/{name}              -> full Service detail (secrets masked)
GET  /api/services/{name}/exports      -> injected env keys (values masked)
GET  /api/services/{name}/logs?follow  -> text/event-stream
GET  /api/topology                     -> { nodes:[{id,name,type,health,managed}],
                                            edges:[{from,to}] }     # from bindings
GET  /api/plan                         -> [ PlanAction ]
POST /api/apply        { rebuild?:bool }-> stream of applied actions
GET  /api/drift                        -> [ DriftFinding ]
GET  /api/backups                      -> [ Backup ]
POST /api/services/{name}/backup       -> { file }
POST /api/services/{name}/restore { file } -> { ok }
POST /api/services/{name}/restart      -> { ok }
GET  /api/doctor                       -> [ { check, ok, fix } ]
```

Field shapes for `Service`, observed state, `PlanAction`, `DriftFinding`, and
`Backup` are exactly as in §2 — those are the response models. The topology
graph and the plan diff are the two views where Perch's model is most worth
visualizing; everything else is tables and a log pane.

### Security notes for the frontend
- Never return resolved secret values (`env[].secret == true`) or managed-service
  exports in clear text — mask to `••••` and surface only the key names.
- `apply`, `restore`, and `destroy` are state-changing and privileged; gate them
  behind auth and a confirm step.
- Managed services are internal-only; do not render public URLs for them.
