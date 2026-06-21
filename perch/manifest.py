"""
Declarative manifest for your apps and agents.

One `perch.yaml` is the source of truth for everything you run. Check it
into Git, review changes in PRs, and let `perch apply` converge your host
to match. Secrets are never stored here -- values use ${ENV_VAR} references
resolved at apply time from the environment (wire to a .env file, your shell,
or a secrets manager in CI).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def resolve_env(value: str) -> str:
    """Expand ${VAR} references from the process environment."""
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in os.environ:
            raise KeyError(f"environment variable ${{{key}}} is referenced but not set")
        return os.environ[key]
    return _ENV_RE.sub(sub, value)


# Secure-by-default. Every container drops all Linux capabilities, can't gain
# new privileges, runs as a non-root user, and gets a read-only root filesystem.
DEFAULT_SECURITY = {
    "read_only_rootfs": True,
    "no_new_privileges": True,
    "drop_caps": ["ALL"],
    "add_caps": [],
    "user": "10001:10001",
}
DEFAULT_RESOURCES = {"memory": "512m", "cpus": "1.0"}
DEFAULT_RESTART = "unless-stopped"

# Service types that map to a managed catalog entry rather than a user build.
MANAGED_TYPES = {"postgres", "cache", "storage", "rest-api", "auth"}
# Non-managed workload types that build + run user code.
WORKLOAD_TYPES = {"webapp", "agent", "function"}


@dataclass
class Build:
    context: str                       # local path OR git URL
    dockerfile: str = "Dockerfile"
    args: dict[str, str] = field(default_factory=dict)
    target: str | None = None          # multi-stage build target


@dataclass
class EnvVar:
    key: str
    value: str
    secret: bool = False

    def resolved(self) -> tuple[str, str]:
        return self.key, resolve_env(self.value)


@dataclass
class Route:
    host: str | None = None            # e.g. app.example.com or app.localhost
    path: str | None = None            # optional path prefix


@dataclass
class Service:
    name: str
    type: str = "webapp"               # webapp | agent | postgres | cache | storage | rest-api
    build: Build | None = None
    image: str | None = None           # use a prebuilt image instead of build
    command: list[str] | None = None
    port: int | None = None            # container port a webapp listens on
    route: Route = field(default_factory=Route)
    env: list[EnvVar] = field(default_factory=list)
    health_path: str | None = None     # HTTP path for a container healthcheck
    schedule: str | None = None        # 5-field cron for agents; omit = long-lived
    security: dict = field(default_factory=lambda: dict(DEFAULT_SECURITY))
    resources: dict = field(default_factory=lambda: dict(DEFAULT_RESOURCES))
    restart: str = DEFAULT_RESTART
    volumes: list[str] = field(default_factory=list)   # "name:/mount" entries
    # ---- managed-service fields (type in MANAGED_TYPES) -----------------
    version: str | None = None         # postgres major version
    extensions: list[str] = field(default_factory=list)   # e.g. [pgvector]
    buckets: list[str] = field(default_factory=list)      # object-storage buckets
    database: str | None = None        # rest-api / auth -> name of a postgres service
    backup: dict | None = None         # {schedule: cron, retain: N}
    bindings: list[str] = field(default_factory=list)     # managed services to wire in
    runtime: str | None = None         # function: node22 | python312 | deno (base image hint)
    # ---- identity (C1/C2) -- opt-in; absent => today's static credential path ---
    identity: "bool | dict | None" = None   # true, or {ttl: <seconds>}: broker per-run creds
    # ---- egress (C8) -- opt-in; absent => today's full outbound internet --------
    egress: "str | dict | None" = None       # all | deny | {allow: [host, ...]}
    # ---- mcp/tool mediation (C9) -- opt-in; absent => no mediation --------------
    mcp: "dict | None" = None                # {allow: [tool-glob, ...]}
    # ---- supply-chain integrity (C12) -- opt-in; absent => no pin enforcement ---
    verify: "dict | None" = None             # {pin: bool, registries: [...]}

    def supply_chain_policy(self):
        if not self.verify:
            return None
        from .supplychain import DigestPolicy
        return DigestPolicy(require_pinned=bool(self.verify.get("pin", False)),
                            allow_registries=self.verify.get("registries"))

    @property
    def egress_policy(self) -> "tuple[str, list]":
        from .egress import policy
        return policy(self.egress)

    @property
    def mcp_enabled(self) -> bool:
        return bool(self.mcp)

    def mcp_policy(self):
        from .mediation import ToolPolicy
        return ToolPolicy((self.mcp or {}).get("allow", []))

    @property
    def identity_enabled(self) -> bool:
        return bool(self.identity)

    @property
    def identity_ttl(self) -> "int | None":
        return self.identity.get("ttl") if isinstance(self.identity, dict) else None

    @property
    def identity_scopes(self) -> dict:
        return self.identity.get("scopes", {}) if isinstance(self.identity, dict) else {}

    def identity_access(self, binding: str) -> str:
        """Least-privilege level for a bound datastore: 'read' or 'write'.
        Defaults to 'write' (preserves the capability a static credential had, so
        opting into identity doesn't silently break writes); narrow per binding
        with `identity: {scopes: {<binding>: read}}`."""
        val = self.identity_scopes.get(binding)
        if val is None:
            return "write"
        return "read" if str(val).strip().lower() in ("read", "ro", "readonly", "read-only") else "write"

    @property
    def is_managed(self) -> bool:
        return self.type in MANAGED_TYPES

    # ---- identity hashes ------------------------------------------------
    def source_hash(self, fingerprint: str = "") -> str:
        """Identity of what gets built/run. `fingerprint` lets a backend mix
        in a content hash of a local build context so code edits rebuild."""
        if self.is_managed:
            return _sha({"type": self.type, "version": self.version,
                         "extensions": sorted(self.extensions), "database": self.database})
        basis = {
            "image": self.image,
            "build": asdict(self.build) if self.build else None,
            "fingerprint": fingerprint,
        }
        return _sha(basis)

    def config_hash(self) -> str:
        """Everything that, if changed, should recreate the container. Secret
        values are included (resolved) so rotation triggers a recreate."""
        env_basis = []
        for e in self.env:
            try:
                k, v = e.resolved()
            except KeyError:
                v = "<unresolved>"
                k = e.key
            env_basis.append([k, _sha({"v": v}) if e.secret else v])
        basis = {
            "type": self.type, "command": self.command, "port": self.port,
            "route": asdict(self.route), "env": sorted(env_basis),
            "health": self.health_path, "schedule": self.schedule,
            "security": self.security, "resources": self.resources,
            "restart": self.restart, "volumes": sorted(self.volumes),
            "buckets": sorted(self.buckets), "database": self.database,
            "backup": self.backup, "bindings": sorted(self.bindings),
        }
        # Only include identity/egress when set, so existing manifests hash exactly
        # as before (no spurious recreate on upgrade); enabling them is a real change.
        if self.identity:
            basis["identity"] = self.identity
        if self.egress:
            basis["egress"] = self.egress
        if self.mcp:
            basis["mcp"] = self.mcp
        if self.verify:
            basis["verify"] = self.verify
        return _sha(basis)

    def resolved_env(self) -> list[tuple[str, str]]:
        return [e.resolved() for e in self.env]

    @staticmethod
    def from_dict(d: dict, defaults: dict) -> "Service":
        build = None
        if "build" in d:
            b = d["build"]
            build = Build(**b) if isinstance(b, dict) else Build(context=b)
        env = [EnvVar(**e) for e in d.get("env", [])]
        route = Route(**d.get("route", {})) if isinstance(d.get("route"), dict) else Route()
        return Service(
            name=d["name"], type=d.get("type", "webapp"), build=build,
            image=d.get("image"), command=d.get("command"),
            port=d.get("port"), route=route, env=env,
            health_path=d.get("health", {}).get("path") if isinstance(d.get("health"), dict) else None,
            schedule=d.get("schedule"),
            security={**DEFAULT_SECURITY, **defaults.get("security", {}), **d.get("security", {})},
            resources={**DEFAULT_RESOURCES, **defaults.get("resources", {}), **d.get("resources", {})},
            restart=d.get("restart", defaults.get("restart", DEFAULT_RESTART)),
            volumes=d.get("volumes", []),
            version=str(d["version"]) if d.get("version") is not None else None,
            extensions=d.get("extensions", []),
            buckets=d.get("buckets", []),
            database=d.get("database"),
            backup=d.get("backup"),
            bindings=d.get("bindings", []),
            runtime=d.get("runtime"),
            identity=d.get("identity"),
            egress=d.get("egress"),
            mcp=d.get("mcp"),
            verify=d.get("verify"),
        )


@dataclass
class Manifest:
    project: str
    services: list[Service] = field(default_factory=list)
    prune: bool = False                # delete managed containers not in the manifest

    @staticmethod
    def load(path: str) -> "Manifest":
        with open(path) as f:
            d = yaml.safe_load(f) or {}
        defaults = d.get("defaults", {})
        return Manifest(
            project=d["project"],
            services=[Service.from_dict(s, defaults) for s in d.get("services", [])],
            prune=bool(d.get("prune", False)),
        )

    def by_name(self) -> dict[str, Service]:
        return {s.name: s for s in self.services}

    def deps(self, svc: Service) -> list[str]:
        """Services that `svc` depends on: its bindings, plus a rest-api/auth database."""
        edges = list(svc.bindings)
        if svc.type in ("rest-api", "auth") and svc.database:
            edges.append(svc.database)
        return [d for d in edges if d in self.by_name()]

    def deploy_order(self) -> list[Service]:
        """Topological sort so managed dependencies converge before their consumers."""
        by_name = self.by_name()
        ordered: list[Service] = []
        seen: set[str] = set()

        def visit(s: Service, stack: set[str]):
            if s.name in seen:
                return
            if s.name in stack:
                raise ValueError(f"dependency cycle involving '{s.name}'")
            stack.add(s.name)
            for dep in self.deps(s):
                visit(by_name[dep], stack)
            stack.discard(s.name)
            seen.add(s.name)
            ordered.append(s)

        for s in self.services:
            visit(s, set())
        return ordered


def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]
