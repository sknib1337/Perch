"""
Backend interface.

The reconciler is backend-agnostic: it diffs desired state (the manifest)
against live state (whatever the backend reports) and asks the backend to
converge. The shipped default is DockerBackend, but anything that can build,
run, and report on long-lived processes can implement this Protocol -- a
Compose backend, a Kubernetes backend, or a remote PaaS API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol, runtime_checkable

from .manifest import Service


@dataclass
class LiveService:
    """What a backend currently runs for one service."""
    name: str
    status: str                       # running | exited | created | missing
    source_hash: str | None = None
    config_hash: str | None = None
    image: str | None = None
    health: str | None = None         # healthy | unhealthy | starting | none


@dataclass
class ManagedSpec:
    """Run configuration for a catalog (managed) service. Produced by catalog.py,
    consumed by the backend instead of a build."""
    image: str
    env: list[tuple[str, str]] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)     # "name:/mount"
    command: list[str] | None = None
    health_cmd: str | None = None
    security: dict = field(default_factory=dict)
    internal_port: int | None = None
    init_sql: str | None = None                          # run on first DB init
    buckets: list[str] = field(default_factory=list)     # object-storage buckets


@dataclass
class RenderContext:
    """Everything a backend needs to materialize one service."""
    project: str
    network: str
    source_hash: str
    config_hash: str
    env: list[tuple[str, str]] = field(default_factory=list)
    spec: ManagedSpec | None = None     # set for managed services; None for build/run apps


@runtime_checkable
class Backend(Protocol):
    def ensure_network(self, project: str) -> str: ...
    def list_managed(self, project: str) -> list[LiveService]: ...
    def get(self, project: str, name: str) -> LiveService | None: ...
    def converge(self, svc: Service, ctx: RenderContext) -> None: ...   # build/spec + (re)create
    def restart(self, project: str, name: str) -> None: ...
    def remove(self, project: str, name: str) -> None: ...
    def logs(self, project: str, name: str, follow: bool = False) -> Iterable[str]: ...
    def run_once(self, svc: Service, ctx: RenderContext) -> int: ...    # one-shot (scheduled agents)
    def fingerprint(self, svc: Service) -> str: ...                     # content hash of local build ctx
    def exec(self, project: str, name: str, cmd: list[str]) -> int: ...  # run a command in a service
