"""
Managed-service catalog -- the "branches" of the backend tree.

Each managed service type maps to a hardened official image plus the run
configuration Perch needs to launch it, and a set of *exports*: the connection
environment variables that dependent workloads receive via `bindings`.

Perch's value is the wiring, hardening, and lifecycle around these proven
components; it does not reimplement databases, identity, or storage.

Supported types:
  postgres   pgvector/pgvector  -> Postgres 16 with the vector extension
  cache      redis              -> Redis with append-only persistence
  storage    minio              -> S3-compatible object storage
  rest-api   postgrest          -> auto-generated REST API over a `postgres` service
  auth       zitadel            -> identity: OIDC/OAuth, users, sessions (needs a `postgres`)
"""

from __future__ import annotations

from .backend import ManagedSpec
from .manifest import Service
from .state import State

MANAGED_TYPES = {"postgres", "cache", "storage", "rest-api", "auth"}

# Managed datastores need to write to their data dir / runtime dirs, so the
# read-only-rootfs default is relaxed for them (a persistent volume holds state).
# Capabilities are still dropped and privilege escalation is still blocked.
_DATASTORE_SECURITY = {
    "read_only_rootfs": False,
    "no_new_privileges": True,
    "drop_caps": ["ALL"],
    "add_caps": [],
    "user": None,            # let the image's entrypoint manage its own uid
}


def cname(project: str, name: str) -> str:
    return f"perch-{project}-{name}"


def spec_for(svc: Service, project: str, state: State, manifest) -> ManagedSpec:
    """Build the run spec for one managed service."""
    if svc.type == "postgres":
        return _postgres(svc, project, state)
    if svc.type == "cache":
        return _cache(svc, project)
    if svc.type == "storage":
        return _storage(svc, project, state)
    if svc.type == "rest-api":
        return _rest_api(svc, project, state, manifest)
    if svc.type == "auth":
        return _auth(svc, project, state, manifest)
    raise ValueError(f"unknown managed type: {svc.type}")


def exports_for(svc: Service, project: str, state: State) -> dict[str, str]:
    """Connection env injected into workloads that bind this service."""
    host = cname(project, svc.name)
    if svc.type == "postgres":
        pw = state.secret(project, svc.name, "password")
        return {
            "PGHOST": host, "PGPORT": "5432", "PGUSER": "app",
            "PGPASSWORD": pw, "PGDATABASE": "app",
            "DATABASE_URL": f"postgresql://app:{pw}@{host}:5432/app",
        }
    if svc.type == "cache":
        return {"REDIS_URL": f"redis://{host}:6379"}
    if svc.type == "storage":
        user = state.secret(project, svc.name, "user", nbytes=12)
        pw = state.secret(project, svc.name, "password")
        return {
            "S3_ENDPOINT": f"http://{host}:9000", "S3_ACCESS_KEY": user,
            "S3_SECRET_KEY": pw, "S3_BUCKETS": ",".join(svc.buckets),
        }
    if svc.type == "rest-api":
        return {"REST_URL": f"http://{host}:3000"}
    if svc.type == "auth":
        return {"AUTH_URL": f"http://{host}:8080",
                "AUTH_ISSUER": f"http://{host}:8080"}
    return {}


# ---- individual catalog entries -----------------------------------------
def _postgres(svc: Service, project: str, state: State) -> ManagedSpec:
    pw = state.secret(project, svc.name, "password")
    version = svc.version or "16"
    env = [
        ("POSTGRES_USER", "app"),
        ("POSTGRES_PASSWORD", pw),
        ("POSTGRES_DB", "app"),
        ("PGDATA", "/var/lib/postgresql/data/pgdata"),
    ]
    # Strip the ambient PUBLIC EXECUTE grant so a least-privilege per-run role (C6)
    # can't call functions it was never granted; the owning `app` role is
    # unaffected. Idempotent, so it's safe to re-run on every converge.
    init = [
        "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC",
    ]
    if "pgvector" in svc.extensions or "vector" in svc.extensions:
        init.append("CREATE EXTENSION IF NOT EXISTS vector")
    return ManagedSpec(
        image=f"pgvector/pgvector:pg{version}",
        env=env,
        volumes=[f"data:/var/lib/postgresql/data"],
        command=None,
        health_cmd="pg_isready -U app -d app || exit 1",
        security=dict(_DATASTORE_SECURITY),
        internal_port=5432,
        init_sql="; ".join(init) + ";",
    )


def _cache(svc: Service, project: str) -> ManagedSpec:
    return ManagedSpec(
        image="redis:7-alpine",
        env=[],
        volumes=["data:/data"],
        command=["redis-server", "--appendonly", "yes"],
        health_cmd="redis-cli ping | grep -q PONG",
        security=dict(_DATASTORE_SECURITY),
        internal_port=6379,
    )


def _storage(svc: Service, project: str, state: State) -> ManagedSpec:
    user = state.secret(project, svc.name, "user", nbytes=12)
    pw = state.secret(project, svc.name, "password")
    return ManagedSpec(
        image="minio/minio:latest",
        env=[("MINIO_ROOT_USER", user), ("MINIO_ROOT_PASSWORD", pw)],
        volumes=["data:/data"],
        command=["server", "/data", "--console-address", ":9001"],
        health_cmd="mc ready local || curl -sf http://127.0.0.1:9000/minio/health/live || exit 1",
        security=dict(_DATASTORE_SECURITY),
        internal_port=9000,
        buckets=list(svc.buckets),
    )


def _rest_api(svc: Service, project: str, state: State, manifest) -> ManagedSpec:
    if not svc.database:
        raise ValueError(f"rest-api '{svc.name}' requires a `database:` referencing a postgres service")
    db = manifest.by_name().get(svc.database)
    if db is None or db.type != "postgres":
        raise ValueError(f"rest-api '{svc.name}' database '{svc.database}' is not a postgres service")
    db_env = exports_for(db, project, state)
    return ManagedSpec(
        image="postgrest/postgrest:latest",
        env=[
            ("PGRST_DB_URI", db_env["DATABASE_URL"]),
            ("PGRST_DB_SCHEMA", "public"),
            ("PGRST_DB_ANON_ROLE", "app"),
            ("PGRST_SERVER_PORT", "3000"),
        ],
        volumes=[],
        command=None,
        health_cmd=None,
        # PostgREST is stateless -> keep it fully hardened.
        security={"read_only_rootfs": True, "no_new_privileges": True,
                  "drop_caps": ["ALL"], "add_caps": [], "user": "10001:10001"},
        internal_port=3000,
    )


def _auth(svc: Service, project: str, state: State, manifest) -> ManagedSpec:
    if not svc.database:
        raise ValueError(f"auth '{svc.name}' requires a `database:` referencing a postgres service")
    db = manifest.by_name().get(svc.database)
    if db is None or db.type != "postgres":
        raise ValueError(f"auth '{svc.name}' database '{svc.database}' is not a postgres service")
    db_env = dict(exports_for(db, project, state))
    masterkey = state.secret(project, svc.name, "masterkey", nbytes=24)[:32].ljust(32, "0")
    host = cname(project, db.name)
    env = [
        ("ZITADEL_MASTERKEY", masterkey),
        ("ZITADEL_EXTERNALSECURE", "false"),
        ("ZITADEL_EXTERNALPORT", "8080"),
        ("ZITADEL_EXTERNALDOMAIN", cname(project, svc.name)),
        ("ZITADEL_TLS_ENABLED", "false"),
        ("ZITADEL_DATABASE_POSTGRES_HOST", host),
        ("ZITADEL_DATABASE_POSTGRES_PORT", "5432"),
        ("ZITADEL_DATABASE_POSTGRES_DATABASE", db_env["PGDATABASE"]),
        ("ZITADEL_DATABASE_POSTGRES_USER_USERNAME", db_env["PGUSER"]),
        ("ZITADEL_DATABASE_POSTGRES_USER_PASSWORD", db_env["PGPASSWORD"]),
        ("ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE", "disable"),
        ("ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME", db_env["PGUSER"]),
        ("ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD", db_env["PGPASSWORD"]),
        ("ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE", "disable"),
    ]
    return ManagedSpec(
        image="ghcr.io/zitadel/zitadel:latest",
        env=env,
        volumes=[],
        command=["start-from-init", "--masterkeyFromEnv", "--tlsMode", "disabled"],
        health_cmd=None,
        security={"read_only_rootfs": False, "no_new_privileges": True,
                  "drop_caps": ["ALL"], "add_caps": [], "user": None},
        internal_port=8080,
    )
