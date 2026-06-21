"""
C5/C6 -- identity-aware managed services (the data plane).

Phase A issues a signed *capability ticket*; this module redeems identity into a
real but ephemeral, least-privilege credential at the datastore itself. When an
identity-enabled workload binds a supported managed service, the reconciler asks a
`DataPlane` to provision a per-run credential scoped to what the workload declared
(read vs. read-write, C6) and valid only for a short TTL, then injects THAT in
place of the permanent service password.

Postgres (this module): a per-run LOGIN role `perch_run_<nonce>` with a random
password, `VALID UNTIL now()+ttl` (native, hard login-expiry), granted only the
privileges its scope allows. Expired roles are reaped (`DROP OWNED BY` + `DROP
ROLE`) so they don't accumulate. Cache (Redis ACL) and storage (MinIO) reuse the
same `DataPlane` seam and are added next.

The SQL/command builders are pure functions (no Docker), so scope and lifecycle
are unit-tested offline; `DockerDataPlane` is the thin glue that runs them via the
backend's `exec`, and `FakeDataPlane` records calls for reconciler tests.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Datastore types that can mint per-identity credentials. Postgres ships here;
# cache/storage are added in the next increment (DockerDataPlane.SUPPORTED).
ALL_TYPES = {"postgres", "cache", "storage"}


class DataPlaneError(RuntimeError):
    """Provisioning or reaping a per-run credential failed."""


@dataclass
class Grant:
    """A request to mint one per-run credential for a verified principal."""
    project: str
    service: str            # the datastore service name (e.g. "db")
    stype: str              # postgres | cache | storage
    access: str             # "read" | "write"
    subject: str            # principal subject (audit / provenance)
    ttl: int
    nonce: str
    issued_at: int
    expires_at: int
    admin: "dict | None" = None    # transient admin creds (storage); never persisted
    buckets: "list | None" = None  # storage buckets to scope to


@runtime_checkable
class DataPlane(Protocol):
    def supports(self, stype: str) -> bool: ...
    def provision(self, grant: Grant) -> "tuple[dict, str]": ...   # (connection env, credential id)
    def reap(self, project: str, stype: str, service: str, credential_ids: list[str],
             admin: "dict | None" = None) -> None: ...


# ---- Postgres: pure builders (unit-tested without Docker) ----------------
def pg_role_name(nonce: str) -> str:
    return f"perch_run_{nonce}"


def pg_provision_sql(role: str, password: str, access: str, ttl: int) -> str:
    """Statements that create a scoped, expiring per-run role. `role` is a Perch-
    generated identifier (perch_run_<hex>, safe), `ttl` an int; the password literal
    is escaped. NOINHERIT prevents any future role-membership grant from
    auto-escalating. Expiry is anchored to the SERVER clock (`now() + interval`)
    rather than a host-rendered timestamp, so host/container clock skew can't extend
    the login window. CREATE + ALTER + GRANTs run as one implicit transaction (a
    single psql -c), so the role is never visible without its expiry set."""
    pw = password.replace("'", "''")
    ttl = int(ttl)
    stmts = [
        f"CREATE ROLE {role} LOGIN NOINHERIT PASSWORD '{pw}'",
        f"DO $$ BEGIN EXECUTE format('ALTER ROLE {role} VALID UNTIL %L', "
        f"(now() + make_interval(secs => {ttl}))::text); END $$",
        f"GRANT CONNECT ON DATABASE app TO {role}",
        f"GRANT USAGE ON SCHEMA public TO {role}",
        f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {role}",
    ]
    if access == "write":
        stmts += [
            f"GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}",
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT, UPDATE, DELETE ON TABLES TO {role}",
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}",
        ]
    return ";\n".join(stmts) + ";"


def pg_reap_expired_sql() -> str:
    """Drop every expired per-run role the server itself reports (self-healing:
    also catches roles orphaned by a crash between provisioning and recording).
    `DROP OWNED BY` first so `DROP ROLE` can't fail on dangling grants."""
    return (
        "DO $$ DECLARE r record; BEGIN "
        "FOR r IN SELECT rolname FROM pg_roles "
        "WHERE rolname LIKE 'perch\\_run\\_%' "
        "AND rolvaliduntil IS NOT NULL AND rolvaliduntil < now() LOOP "
        "EXECUTE format('DROP OWNED BY %I', r.rolname); "
        "EXECUTE format('DROP ROLE %I', r.rolname); "
        "END LOOP; END $$;"
    )


def pg_connection_env(project: str, service: str, role: str, password: str) -> dict:
    host = f"perch-{project}-{service}"
    return {
        "PGHOST": host, "PGPORT": "5432", "PGUSER": role, "PGPASSWORD": password,
        "PGDATABASE": "app",
        "DATABASE_URL": f"postgresql://{role}:{password}@{host}:5432/app",
    }


# ---- Redis (cache): per-run ACL user -------------------------------------
def redis_user_name(nonce: str) -> str:
    return f"perch_run_{nonce}"


def redis_acl_setuser_args(user: str, password: str, access: str) -> list:
    """`reset` clears any prior grants; `~*` all keys. Both tiers exclude
    @dangerous (FLUSHALL/CONFIG/SHUTDOWN/KEYS/...): read keeps @read minus those
    (SCAN/GET/... remain), write gets all data commands but no admin/destructive
    ones. Redis ACL has no native expiry, so these users are reaped on TTL."""
    cats = ["+@read", "-@dangerous"] if access == "read" else ["+@all", "-@dangerous"]
    return ["redis-cli", "ACL", "SETUSER", user, "reset", "on", f">{password}", "~*", *cats]


def redis_acl_deluser_args(user: str) -> list:
    return ["redis-cli", "ACL", "DELUSER", user]


def redis_connection_env(project: str, service: str, user: str, password: str) -> dict:
    host = f"perch-{project}-{service}"
    return {"REDIS_URL": f"redis://{user}:{password}@{host}:6379"}


# ---- MinIO (storage): per-run user + built-in policy ---------------------
_MINIO_ALIAS = "local"
_MINIO_ENDPOINT = "http://127.0.0.1:9000"


def minio_user_name(nonce: str) -> str:
    return f"perch_run_{nonce}"


def minio_provision_commands(admin_user: str, admin_pw: str, access_key: str,
                             secret_key: str, access: str) -> list:
    """mc commands to create a per-run user and attach a built-in policy
    (readonly | readwrite) -- verb-scoped (C6). NOTE: the built-in policies span
    all buckets; per-bucket scoping is a documented residual (it needs an inline
    policy doc, which mc only loads from a file/stdin we can't assume in the
    container)."""
    policy = "readonly" if access == "read" else "readwrite"
    return [
        ["mc", "alias", "set", _MINIO_ALIAS, _MINIO_ENDPOINT, admin_user, admin_pw],
        ["mc", "admin", "user", "add", _MINIO_ALIAS, access_key, secret_key],
        ["mc", "admin", "policy", "attach", _MINIO_ALIAS, policy, "--user", access_key],
    ]


def minio_alias_args(admin_user: str, admin_pw: str) -> list:
    return ["mc", "alias", "set", _MINIO_ALIAS, _MINIO_ENDPOINT, admin_user, admin_pw]


def minio_connection_env(project: str, service: str, access_key: str,
                         secret_key: str, buckets: list) -> dict:
    host = f"perch-{project}-{service}"
    return {"S3_ENDPOINT": f"http://{host}:9000", "S3_ACCESS_KEY": access_key,
            "S3_SECRET_KEY": secret_key, "S3_BUCKETS": ",".join(buckets or [])}


# ---- Docker-backed implementation ---------------------------------------
class DockerDataPlane:
    """Provisions per-run credentials by running datastore commands through the
    backend's `exec`. Backend-agnostic: anything implementing `exec(project,
    service, cmd) -> int` works."""

    SUPPORTED = {"postgres", "cache", "storage"}

    def __init__(self, backend, clock=time.time):
        self.b = backend
        self.clock = clock

    def supports(self, stype: str) -> bool:
        return stype in self.SUPPORTED

    def provision(self, grant: Grant) -> "tuple[dict, str]":
        if grant.stype == "postgres":
            return self._provision_postgres(grant)
        if grant.stype == "cache":
            return self._provision_cache(grant)
        if grant.stype == "storage":
            return self._provision_storage(grant)
        raise DataPlaneError(f"unsupported datastore type {grant.stype!r}")

    def reap(self, project: str, stype: str, service: str, credential_ids: list[str],
             admin: "dict | None" = None) -> None:
        if stype == "postgres":
            self._reap_postgres(project, service, credential_ids)
        elif stype == "cache":
            self._reap_cache(project, service, credential_ids)
        elif stype == "storage":
            self._reap_storage(project, service, credential_ids, admin)

    def _wait_ready(self, project: str, service: str, probe: list, tries: int = 30) -> None:
        for _ in range(tries):
            if self.b.exec(project, service, probe) == 0:
                return
            time.sleep(1)
        raise DataPlaneError(f"{service!r} not ready for provisioning")

    def _provision_postgres(self, grant: Grant) -> "tuple[dict, str]":
        # Per-run provisioning connects to the DB, so wait for it to be ready
        # (cold start / rebuild) before issuing SQL.
        self._wait_ready(grant.project, grant.service, ["pg_isready", "-U", "app"])
        role = pg_role_name(grant.nonce)
        password = secrets.token_urlsafe(24)
        sql = pg_provision_sql(role, password, grant.access, grant.ttl)
        rc = self.b.exec(grant.project, grant.service,
                         ["psql", "-U", "app", "-d", "app", "-v", "ON_ERROR_STOP=1", "-c", sql])
        if rc != 0:
            raise DataPlaneError(
                f"could not provision a per-run postgres role on {grant.service!r}")
        return pg_connection_env(grant.project, grant.service, role, password), role

    def _reap_postgres(self, project: str, service: str, roles: list[str]) -> None:
        # Native sweep: drops ALL expired per-run roles (tracked or orphaned).
        # Raises on failure so the reconciler keeps the records and retries.
        rc = self.b.exec(project, service,
                         ["psql", "-U", "app", "-d", "app", "-v", "ON_ERROR_STOP=1", "-c", pg_reap_expired_sql()])
        if rc != 0:
            raise DataPlaneError(f"failed to reap expired postgres roles on {service!r}")

    # -- cache (Redis ACL user) -------------------------------------------
    def _provision_cache(self, grant: Grant) -> "tuple[dict, str]":
        self._wait_ready(grant.project, grant.service, ["redis-cli", "PING"])
        user = redis_user_name(grant.nonce)
        password = secrets.token_urlsafe(24)
        if self.b.exec(grant.project, grant.service,
                       redis_acl_setuser_args(user, password, grant.access)) != 0:
            raise DataPlaneError(f"could not provision a per-run cache user on {grant.service!r}")
        return redis_connection_env(grant.project, grant.service, user, password), user

    def _reap_cache(self, project: str, service: str, users: list[str]) -> None:
        failed = False
        for user in users:                       # ACL DELUSER is idempotent (rc 0)
            if self.b.exec(project, service, redis_acl_deluser_args(user)) != 0:
                failed = True
        if failed:
            raise DataPlaneError(f"failed to reap cache users on {service!r}")

    # -- storage (MinIO user + built-in policy) ---------------------------
    def _provision_storage(self, grant: Grant) -> "tuple[dict, str]":
        admin = grant.admin or {}
        access_key = minio_user_name(grant.nonce)
        secret_key = secrets.token_hex(24)       # hex: never starts with '-' (no mc flag misparse)
        cmds = minio_provision_commands(admin.get("user", ""), admin.get("password", ""),
                                        access_key, secret_key, grant.access)
        # The first command (alias set) doubles as the readiness/auth check.
        for i, cmd in enumerate(cmds):
            if self.b.exec(grant.project, grant.service, cmd) != 0:
                if i == 0:                       # not ready yet -> retry the alias set
                    self._wait_ready(grant.project, grant.service, cmd)
                    continue
                raise DataPlaneError(f"could not provision a per-run storage user on {grant.service!r}")
        env = minio_connection_env(grant.project, grant.service, access_key, secret_key, grant.buckets)
        return env, access_key

    def _reap_storage(self, project: str, service: str, users: list[str], admin: "dict | None") -> None:
        admin = admin or {}
        self.b.exec(project, service, minio_alias_args(admin.get("user", ""), admin.get("password", "")))
        failed = []
        for user in users:
            # Idempotent: a user that's already gone is a successful reap.
            if self.b.exec(project, service, ["mc", "admin", "user", "info", _MINIO_ALIAS, user]) != 0:
                continue
            if self.b.exec(project, service, ["mc", "admin", "user", "remove", _MINIO_ALIAS, user]) != 0:
                failed.append(user)
        if failed:
            raise DataPlaneError(f"failed to reap storage users {failed} on {service!r}")


# ---- offline test double -------------------------------------------------
class FakeDataPlane:
    """Records provision/reap calls and returns deterministic credentials, so the
    reconciler's data-plane wiring is tested without Docker."""

    def __init__(self, supported=("postgres", "cache", "storage")):
        self.supported = set(supported)
        self.provisioned: list[Grant] = []
        self.reaped: list[tuple] = []

    def supports(self, stype: str) -> bool:
        return stype in self.supported

    def provision(self, grant: Grant) -> "tuple[dict, str]":
        self.provisioned.append(grant)
        cid = f"perch_run_{grant.nonce}"
        host = f"perch-{grant.project}-{grant.service}"
        if grant.stype == "cache":
            env = {"REDIS_URL": f"redis://{cid}:fakepw@{host}:6379"}
        elif grant.stype == "storage":
            env = {"S3_ENDPOINT": f"http://{host}:9000", "S3_ACCESS_KEY": cid,
                   "S3_SECRET_KEY": "fakepw", "S3_BUCKETS": ",".join(grant.buckets or [])}
        else:
            env = {"DATABASE_URL": f"postgresql://{cid}:fakepw@{host}:5432/app",
                   "PGUSER": cid}
        env["PERCH_ACCESS"] = grant.access
        return env, cid

    def reap(self, project: str, stype: str, service: str, credential_ids: list[str],
             admin: "dict | None" = None) -> None:
        self.reaped.append((stype, service, list(credential_ids)))
