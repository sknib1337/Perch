"""
Reconciler: converge live state to the manifest. Idempotent and backend-agnostic.

  plan()  -> Actions, no side effects
  apply() -> execute the plan
  drift() -> read-only report of anything that diverged (cron this)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import catalog
from .backend import Backend, RenderContext
from .manifest import Manifest, Service
from .state import State


@dataclass
class Action:
    kind: str          # create | rebuild | reconfigure | restart | prune | noop
    target: str
    detail: str = ""


_ICON = {"create": "+", "rebuild": "^", "reconfigure": "~",
         "restart": "*", "prune": "-", "noop": "="}


class Reconciler:
    def __init__(self, backend: Backend, manifest: Manifest, force_rebuild: bool = False,
                 state: State | None = None):
        self.b = backend
        self.m = manifest
        self.force = force_rebuild
        self.state = state or State()

    def _binding_env(self, svc: Service) -> list[tuple[str, str]]:
        """Connection env for every managed service this workload binds."""
        env: list[tuple[str, str]] = []
        for dep_name in svc.bindings:
            dep = self.m.by_name().get(dep_name)
            if dep and dep.is_managed:
                env += list(catalog.exports_for(dep, self.m.project, self.state).items())
        return env

    def _ctx(self, svc: Service) -> RenderContext:
        net = f"perch-{self.m.project}"
        fp = self.b.fingerprint(svc)
        env = svc.resolved_env() + self._binding_env(svc)
        spec = None
        if svc.is_managed:
            spec = catalog.spec_for(svc, self.m.project, self.state, self.m)
        return RenderContext(
            project=self.m.project, network=net,
            source_hash=svc.source_hash(fp), config_hash=svc.config_hash(),
            env=env, spec=spec,
        )

    def plan(self) -> list[Action]:
        actions: list[Action] = []
        live_by_name = {ls.name: ls for ls in self.b.list_managed(self.m.project)}
        for svc in self.m.deploy_order():
            ctx = self._ctx(svc)
            live = live_by_name.get(svc.name)
            if live is None:
                actions.append(Action("create", svc.name, _src(svc)))
            elif self.force or (live.source_hash != ctx.source_hash):
                actions.append(Action("rebuild", svc.name, "source changed"))
            elif live.config_hash != ctx.config_hash:
                actions.append(Action("reconfigure", svc.name, "config changed"))
            elif live.status != "running" and not svc.schedule:
                actions.append(Action("restart", svc.name, f"status={live.status}"))
            else:
                actions.append(Action("noop", svc.name, "up to date"))
        if self.m.prune:
            wanted = self.m.by_name()
            for name in live_by_name:
                if name not in wanted:
                    actions.append(Action("prune", name, "not in manifest"))
        return actions

    def apply(self, on_action: Callable[[Action], None] | None = None) -> None:
        self.b.ensure_network(self.m.project)
        plan = self.plan()
        by_name = self.m.by_name()
        # apply in dependency order so a freshly-created DB exists before its consumers
        order = {s.name: i for i, s in enumerate(self.m.deploy_order())}
        actionable = sorted(plan, key=lambda a: order.get(a.target, 1_000_000))
        for a in actionable:
            if on_action:
                on_action(a)
            if a.kind in ("create", "rebuild", "reconfigure"):
                svc = by_name[a.target]
                self.b.converge(svc, self._ctx(svc))
            elif a.kind == "restart":
                self.b.restart(self.m.project, a.target)
            elif a.kind == "prune":
                self.b.remove(self.m.project, a.target)

    def drift(self) -> list[str]:
        report: list[str] = []
        live_by_name = {ls.name: ls for ls in self.b.list_managed(self.m.project)}
        wanted = self.m.by_name()
        for svc in self.m.services:
            ctx = self._ctx(svc)
            live = live_by_name.get(svc.name)
            if live is None:
                report.append(f"MISSING    {svc.name}: declared but not running")
                continue
            if live.source_hash != ctx.source_hash:
                report.append(f"STALE      {svc.name}: built from older source")
            if live.config_hash != ctx.config_hash:
                report.append(f"DRIFT      {svc.name}: live config differs from manifest")
            if not svc.schedule and live.status != "running":
                report.append(f"DOWN       {svc.name}: status={live.status}")
            if live.health == "unhealthy":
                report.append(f"UNHEALTHY  {svc.name}: failing healthcheck")
        for name in live_by_name:
            if name not in wanted:
                report.append(f"UNMANAGED  {name}: running but not in manifest")
        return report

    @staticmethod
    def icon(kind: str) -> str:
        return _ICON.get(kind, " ")


def _src(svc: Service) -> str:
    if svc.is_managed:
        return f"{svc.type} (managed)"
    if svc.image:
        return svc.image
    return svc.build.context if svc.build else "?"
