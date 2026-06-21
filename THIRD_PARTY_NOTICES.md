# Third-Party Notices

Perch is original work licensed under Apache-2.0 (see LICENSE and NOTICE). It does
not vendor (copy into this repository) third-party source code, with the single
exception of its runtime dependency below. Everything else is *referenced* at
runtime — container images are pulled from upstream registries, and the web
console loads fonts/libraries from public CDNs — so this repository does not
redistribute their copyrighted code. Each component stays under its own license;
when you deploy them, comply with the license of each.

License names below are given in good faith and can change upstream over time;
verify against each project. This file is not legal advice.

## Bundled (installed as a Python dependency)

| Component | Purpose | License |
|---|---|---|
| PyYAML | Manifest parsing | MIT |

Dev-only tools (not shipped to users): pytest, build, twine.

## Referenced container images (pulled at runtime, not bundled)

| Image | Used for | Upstream license |
|---|---|---|
| pgvector/pgvector | `postgres` | PostgreSQL License |
| redis | `cache` | See upstream (Redis licensing has changed across versions) |
| minio/minio | `storage` | See upstream (AGPL-3.0) — Perch neither modifies nor bundles it |
| postgrest/postgrest | `rest-api` | MIT |
| ghcr.io/zitadel/zitadel | `auth` | Apache-2.0 |
| caddy | the reverse proxy | Apache-2.0 |

## Referenced by the web console (loaded from public CDNs, not bundled)

| Resource | License |
|---|---|
| Tailwind CSS | MIT |
| Inter (font) | SIL Open Font License 1.1 |
| JetBrains Mono (font) | SIL Open Font License 1.1 |
| Material Symbols (icons) | Apache-2.0 |

## Documents adopted into this repository

| Document | Source | License |
|---|---|---|
| CODE_OF_CONDUCT.md | Contributor Covenant 2.1 | CC BY 4.0 |
| LICENSE | Apache License 2.0 | (the license text itself) |
