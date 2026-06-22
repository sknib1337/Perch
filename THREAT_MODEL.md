# Perch Threat Model

> Status: living document. This describes the security posture Perch is being
> built toward — a **secure-by-default runtime for self-hosted AI agents** — and
> the concrete controls that implement it. Each control is tagged with the phase
> in which it lands. Controls marked **Implemented** ship today; the rest are
> defined here so the design has a fixed target, but are not yet in the code.

## 1. Premise

Perch runs other people's apps and **AI agents** on infrastructure you operate.
Agents are a distinct class of workload: they are driven by model output and
external input, they call tools and managed services on their own initiative,
and a single prompt-injection or model mistake can turn a trusted agent into a
confused deputy. The classic "inject a long-lived `DATABASE_URL` into the
container and hope" pattern fails badly here — one compromised agent leaks a
credential that is valid forever, for everything it was ever bound to.

Perch's answer: **every workload gets its own short-lived, least-privilege
identity and holds no long-lived secrets.** Identity is cryptographic and
per-agent; credentials are minted per run, scoped, and expire on their own;
the thing that mints them refuses to do so unless it can attest *what* is asking.

## 2. Assets (what we protect)

| Asset | Why it matters |
| --- | --- |
| Managed-service credentials (Postgres, storage, cache, auth) | Direct access to user data. Today persisted in `.perch/state.json`. |
| The state file `.perch/state.json` | Root of trust for every managed credential; a copy is a full compromise. |
| Per-agent identity keys | Let an agent prove who it is and obtain credentials. |
| The control plane (CLI + HTTP API/console) | Can deploy, restart, read logs, trigger backups — full operational control. |
| User code & build context | Tampering changes what runs under a trusted identity. |
| The host & Docker socket | Ultimate authority; out of scope to defend from itself (see §5). |

## 3. Trust boundaries

```text
   operator (you) ──TLS/SSH──▶ control plane (CLI / API) ──▶ Docker ──▶ containers
                                      │                                   │
                                      ▼                                   ▼
                              .perch/state.json                  workload (app / AGENT)
                                 (secrets)                          │  no long-lived secret
                                      ▲                             ▼
                                      └──────── credential broker ◀── proves identity + attests
                                                  (mints scoped, short-TTL creds)
```

- **Operator ↔ control plane** — authenticated, ideally over localhost/SSH/TLS.
- **Control plane ↔ workload** — the workload is *semi-trusted*: it runs our
  hardening, but its behavior is steered by untrusted model/user input.
- **Workload ↔ managed service** — must be mediated by per-identity, per-run
  credentials, not a static secret baked into the container.
- **At rest** — the state file is assumed to be copyable by an attacker who
  reaches the disk, a backup, or a stray `scp`. It must not yield cleartext keys.

## 4. Adversaries

1. **Compromised / manipulated agent** (primary). Prompt-injected or buggy; runs
   trusted code but issues attacker-chosen actions. Wants to exfiltrate data,
   reach services it was never bound to, or persist.
2. **Read-only disk/backup attacker.** Obtains a copy of `.perch/state.json` or a
   backup tarball. Wants the credentials inside.
3. **Network-adjacent attacker.** Can reach the control-plane API or sit between
   containers on the host network. Wants to drive the control plane or harvest
   credentials in transit.
4. **Malicious or swapped image / build context.** Wants a different artifact to
   run under a legitimate workload's identity and inherit its access.

## 5. Out of scope (assumptions)

- The host kernel, the Docker daemon, and root on the box are trusted. Anyone with
  the Docker socket or root already owns every container; Perch does not defend
  against the platform operator.
- Perch does not reimplement databases, auth, or storage — it hardens, wires, and
  brokers access to proven components (see `catalog.py`).
- Side-channel, supply-chain-of-the-host, and physical attacks are out of scope
  except where a named control (C12) explicitly addresses them.

## 6. Controls

Each control names the threat it addresses, the mechanism, and the residual risk.
Status is **Implemented** (in the codebase now) or **Planned** (designed, not yet
built — target phase noted). Backwards compatibility is a hard rule: every control
is opt-in and absent configuration must behave exactly as the prior release.

### Phase A — the identity spine (Implemented)

> Phase A is delivered as one changeset, landed control-by-control in separate
> commits (C2 identity, then C1 broker, C3 attestation, C4 sealed state, C7 API
> auth). A control's "Module:" reference is satisfied by the end of the changeset;
> mid-series commits may precede the consumer that wires it in.

**C1 — Short-lived, scoped credential broker.** *Threat: 1, 2.*
Instead of injecting a permanent `DATABASE_URL`, the broker derives a per-run,
scoped, short-TTL credential from a *verified* principal and hands the workload an
ephemeral credential reference. Scope is limited to the services the principal is
actually bound to; expiry is enforced on every use. The legacy static-injection
path remains the default and is unchanged when identity is not configured.
TTLs are bounded by a hard ceiling so the short-lived property cannot be configured
away, and issuance fails closed on a bad/oversized/non-numeric TTL.
*Residual:* in Phase A the broker issues signed capability tickets; binding them
to real per-run datastore roles is C5 (Phase B). The issuer signing key and any
HMAC identity secrets are sealed at rest by C4 (below). Module: `perch/broker.py`.

**C2 — Per-agent cryptographic identity.** *Threat: 1, 4.*
At provision time each workload receives a stable subject identifier and a freshly
generated key. It can sign a challenge; the broker verifies the signature before
issuing anything. Identities are self-describing (they carry their algorithm), so
the verifier always selects the matching scheme and a downgrade is detectable.
Default signing is HMAC-SHA256 (stdlib, single-host issuer == verifier); when the
optional `cryptography` extra is installed, Ed25519 keypairs are used so the
broker can verify with a public key it cannot forge with. Verification goes
through a trusted `IdentityStore` keyed by subject, so a requester can never
dictate the algorithm or key used to check it (this is what structurally closes
an Ed25519->HMAC downgrade); each scheme also domain-separates its signed bytes.
Module: `perch/identity.py`.
*Residual:* key custody inside a live container is only as strong as the container
boundary; rotation/revocation lifecycle is tracked for a later phase.

**C3 — Attestation before issuance.** *Threat: 1, 4.*
The broker will not mint a credential for an instance it cannot attest. Building on
the existing `source_hash` / `config_hash` machinery, the requester must present an
attestation (image/source identity + config hash + expected host) that matches the
manifest-derived expectation for that subject. Any mismatch — swapped image, drifted
config, wrong container host, or wrong subject — is denied, closed. When a broker
has an attestor configured (as the reconciler wires it for every identity-enabled
workload), issuance *requires* a matching attestation. Module: `perch/attest.py`
(consumed by the broker).
*Residual:* attestation is as strong as the reported image identity; cryptographic
image-digest pinning and signed provenance harden this further under C12.

**C4 — Sealed secrets at rest.** *Threat: 2.*
Secrets in `.perch/state.json` are envelope-encrypted with a key from a pluggable
key provider. This covers not only managed-service credential slots but the
highest-value identity-spine material: the broker issuer signing key
(`_broker/issuer`) and any HMAC identity verification secrets (`_identities`) —
both ticket/identity-forging material if read in clear. Copying the state file
yields ciphertext and an algorithm tag, not credentials. The default local provider
uses only the stdlib (HKDF-derived keystream with encrypt-then-MAC and constant-time
verification); the `cryptography` extra swaps in Fernet (AES-128-CBC + HMAC). With
no key configured, behavior is identical to the prior release (cleartext slots), so
upgrades are safe and migration is lazy. Modules: `perch/crypto.py`, `perch/state.py`.
*Residual:* the master key must live somewhere; the default keeps it in an env var
or a key file (0600 on POSIX; on Windows it inherits the directory ACL) on the same
host, and must be high-entropy (keys under 16 bytes are rejected). External KMS/HSM
providers plug into the same seam.

**C7 — Authenticated control plane.** *Threat: 3.*
The HTTP API gains opt-in bearer-token authentication and a minimal role check
(`viewer` may read; `admin` may apply/restart/backup). Unauthenticated requests get
`401`; authenticated-but-out-of-scope requests get `403`. Enabled with
`perch serve --require-auth`; with auth unconfigured, the server keeps today's
localhost-only, unauthenticated behavior. Module: `perch/api.py`.
*Residual:* tokens are bearer credentials — pair with TLS/SSH for remote use. Auth
covers the HTTP API, not the local CLI (which already implies host access).

### Phase B — identity-aware data plane (Implemented)

> Like Phase A, delivered control-by-control across one changeset. A `DataPlane`
> seam (`perch/dataplane.py`) redeems an identity-enabled binding into a real but
> ephemeral, scoped credential at the datastore itself, injected in place of the
> static service password. With no identity, the static credential path is
> unchanged.

**C5 — Identity-aware managed services.** *Threat: 1.*
Supported datastores mint a genuine per-run credential for the verified, attested
principal: Postgres a `LOGIN` role expiring on the server clock (`VALID UNTIL`),
Redis a per-run ACL user, MinIO a per-run access key. Credentials are reaped on
expiry (Postgres self-heals via a native expired-role sweep; Redis/MinIO users are
removed on TTL). The control plane never persists the per-run passwords -- only the
credential id and expiry, for reaping. Module: `perch/dataplane.py`.
*Residual:* the datastore's bootstrap account (Postgres `app`, the Redis default
user, the MinIO root key) still exists; per-run least privilege is strongest when a
datastore is consumed only via identity, not also bound statically. Locking the
bootstrap account down is a follow-on hardening.

**C6 — Least-privilege data scopes.** *Threat: 1.*
Each binding declares `identity: {scopes: {<svc>: read|write}}`; the per-run
credential is granted only what the scope allows — Postgres `SELECT` vs.
`SELECT`+DML (with `NOINHERIT` and PUBLIC `EXECUTE` revoked at bootstrap), Redis
`+@read -@dangerous` vs. `+@all -@dangerous`, MinIO `readonly` vs. `readwrite`.
Default is read-write (preserves the capability a static credential had, so opting
into identity doesn't silently break writes); narrowing to read is one line.
*Residual:* MinIO scoping is verb-level across the instance's buckets; per-bucket
scoping (an inline policy) is a noted follow-on, as is keeping admin creds out of
`mc`'s argv.

### Phase C — runtime containment (Implemented)

> Delivered control-by-control across one changeset. Opt-in and backwards
> compatible: absent the new config, networking and behavior are unchanged.

**C8 — Egress control / network segmentation.** *Threat: 1.*
A workload declares `egress: all | deny | {allow: [host]}`. Enforcement is network
level: deny/allow workloads run on an `--internal` Docker network with no IP route
off-box (managed services attach to both nets so they stay reachable), and `allow`
adds a per-workload default-deny forward proxy (the only internet path, forwarding
only the allowlisted hosts). Policy fails closed. Module: `perch/egress.py`.
*Residual:* Docker's embedded DNS still resolves upstream, so DNS is a low-bandwidth
covert channel; and a workload given a managed service's *admin* credential could
relay outbound through that service (e.g. MinIO webhooks) -- use identity-scoped,
non-admin creds (C5/C6) for restricted agents. Per-workload isolated networks and a
filtering resolver are follow-ons.

**C9 — MCP & tool-call mediation.** *Threat: 1.*
An agent declares what it may use (`mcp: {servers, allow: {tools, resources, prompts},
sampling, completion}`); a per-agent **mediating gateway** sidecar
(`perch/gateway.py`) authorizes every MCP message against that default-deny policy
and forwards only what's allowed to the configured upstream servers (HTTP or local
stdio). The full method surface is covered: `tools/call`, `resources/read`,
`prompts/get` are authorized by target; `*/list` responses are filtered to the
allowlist so the model never sees a disallowed capability; server-initiated
`sampling/createMessage` and `completion/complete` are denied unless explicitly
enabled; unknown/malformed messages fail closed. The agent's MCP client is pointed
at the gateway (`PERCH_MCP_GATEWAY`); paired with C8 (the agent's only outbound path
is the gateway) it cannot route around it. Wildcards never cross the `server.tool`
boundary, pattern metacharacters are literal, names are validated rather than silently
normalized (Unicode-whitespace tricks are refused), and the HTTP front bounds body
size, batch length, and slow-client time so a hostile agent can't exhaust it. Each
decision is appended to a spool the reconciler atomically claims and folds into the
C10/C11 tamper-evident audit log; repeated tool denials trip the `Detector` and
quarantine the subject, and the reconciler restarts the gateway so it denies that
subject outright (a compromised agent that also uses `identity:` loses its brokered
credentials too). Modules: `perch/mediation.py` (policy), `perch/mcp.py` (protocol
decision core), `perch/gateway.py` (the sidecar).
*Residuals:* v1 trusts the network boundary — the per-agent gateway has no per-request
auth, so any container on the project internal net could use it; close this with
broker-token auth (an `mcp`-resource credential the gateway verifies) or a per-agent
network. stdio servers run inside the gateway image, which must carry their runtime
(prefer HTTP upstreams for hostile workloads). Server→agent streaming (SSE) and a
reverse sampling channel aren't proxied (denied by default). Detection is
threshold-based over the bounded audit window (shared with C11): denials paced below
the truncation horizon can evade the counter. DNS remains a covert channel (shared
with C8).

**C10 — Agent memory integrity & provenance.** *Threat: 1.*
A tamper-evident, append-only memory log: a per-record hash chain gives provenance
and catches edits/reordering/insertion, and an HMAC anchor over (length, head) --
keyed by a secret Perch holds, not the agent -- catches truncation and whole-chain
rewrites an attacker without the key can't reproduce. Inputs are canonicalized
(string keys, no NaN/Inf) so the hash is injective. Module: `perch/memory.py`.

### Phase D — detection (Implemented)

**C11 — Tamper-evident audit & anomaly response.** *Threat: 1, 2.*
The broker records its security signals -- issuance, out-of-scope denials,
attestation and identity-proof failures -- into a tamper-evident `AuditLog` (the
C10 hash chain + MAC anchor, so an attacker can't quietly erase their tracks). A
`Detector` applies threshold rules over the events (repeated denials / attestation
or proof failures for a subject), and flagged subjects are added to a `Quarantine`
the broker checks both at issuance and at redemption (an outstanding ticket is
revoked, not just future ones), closed. The reconciler wires this into the broker:
the audit log is anchored and persisted to sealed state every run and verified on
load -- a rewritten log fails closed. Module: `perch/audit.py`.
*Residual:* detection is threshold-based, not behavioral ML; the audit window is
bounded (older events age out of the tamper-evident window unless anchored off-box).

### Phase E — supply chain (Implemented)

**C12 — Supply-chain integrity.** *Threat: 4.*
A workload opts into `verify: {pin: true, registries: [...]}`; before it runs, the
declared image must be pinned to a full `sha256:<64 hex>` digest (a mutable tag or
malformed digest is refused, closed) and pulled only from an allow-listed registry.
The check resolves the *catalog* image for managed services (not just `svc.image`),
so a managed service's `:latest` can't slip the policy, and runs on every
materialization path (apply, `perch run`, scheduler). Re-verifying the actually
pulled digest against the pin is a backend hook that fails closed if the digest
can't be resolved. Module: `perch/supplychain.py`.
*Residual:* image *signature*/SBOM verification (cosign/in-toto) is a further
hardening on top of digest pinning; the catalog's own images aren't pinned by
default (pin them via `verify` + an overridden image, or pin them in the catalog).

## 7. Control ↔ threat coverage

| Adversary | Covered now (Phase A) | Hardened later |
| --- | --- | --- |
| 1. Compromised agent | C1 (scoped, expiring creds), C2 (must prove identity), C3 (attested) | C5, C6, C8, C9, C10 |
| 2. Disk/backup attacker | C4 (sealed at rest) | C11 (detect exfil), C12 |
| 3. Network-adjacent | C7 (authn + RBAC on the API) | C8 (segmentation) |
| 4. Malicious image/build | C3 (attestation deny-on-mismatch), C2 | C12 (provenance/signing) |

## 8. Backwards-compatibility contract

Absent the new configuration, Perch behaves byte-for-byte as the prior release:
static credential injection (no broker), cleartext state (no key provider), and an
unauthenticated localhost API. Security is opt-in and additive; the offline test
suite enforces that the legacy paths stay green.
