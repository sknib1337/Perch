"""
Reconciler: converge live state to the manifest. Idempotent and backend-agnostic.

  plan()  -> Actions, no side effects
  apply() -> execute the plan
  drift() -> read-only report of anything that diverged (cron this)
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from . import attest as attest_mod
from . import audit as audit_mod
from . import broker as broker_mod
from . import catalog
from . import dataplane as dataplane_mod
from . import egress as egress_mod
from . import identity as identity_mod
from .backend import Backend, RenderContext
from .identity import IdentityStore
from .manifest import Manifest, Service
from .state import State

# Reserved state keys for the identity spine (C1/C2); sealed at rest by C4.
_IDSTORE_KEY = "_identities"
_BROKER_KEY = "_broker/issuer"
_DATAPLANE_KEY = "_dataplane"          # per-run credential records pending reaping (C5)
_AUDIT_KEY = "_audit"                  # C11 tamper-evident audit log
_AUDIT_ANCHOR_KEY = "_audit/anchor"    # C11 MAC anchor over the audit log
_QUARANTINE_KEY = "_quarantine"        # C11 quarantined subjects
_AUDIT_MAX_EVENTS = 5000               # bound state growth (older events age out)


def _envname(name: str) -> str:
    """A safe environment-variable suffix for a binding name."""
    return re.sub(r"[^A-Z0-9_]", "_", name.upper())


@dataclass
class Action:
    kind: str          # create | rebuild | reconfigure | restart | prune | noop
    target: str
    detail: str = ""


_ICON = {"create": "+", "rebuild": "^", "reconfigure": "~",
         "restart": "*", "prune": "-", "noop": "="}


class Reconciler:
    def __init__(self, backend: Backend, manifest: Manifest, force_rebuild: bool = False,
                 state: State | None = None, broker=None, dataplane=None):
        self.b = backend
        self.m = manifest
        self.force = force_rebuild
        self.state = state or State()
        self._broker = broker            # injectable; built lazily from state otherwise
        self._idstore: IdentityStore | None = None
        self._attestor = None
        self._dataplane = dataplane      # injectable; defaults to DockerDataPlane(backend)
        self._audit = None               # C11: tamper-evident audit log
        self._quarantine = None          # C11: quarantined subjects
        self._audit_key = None           # C11: anchor key (from sealed state)

    def _binding_env(self, svc: Service, mint: bool = False) -> list[tuple[str, str]]:
        """Connection env for every managed service this workload binds.

        Default (no `identity:`): today's static credential injection. With
        identity enabled, route through the broker (C1) so the workload gets an
        ephemeral, scoped credential reference instead of a permanent secret.
        """
        if svc.identity_enabled:
            return self._brokered_binding_env(svc, mint=mint)
        env: list[tuple[str, str]] = []
        for dep_name in svc.bindings:
            dep = self.m.by_name().get(dep_name)
            if dep and dep.is_managed:
                env += list(catalog.exports_for(dep, self.m.project, self.state).items())
        return env

    def _ensure_broker(self):
        """Lazily build (or adopt an injected) broker + identity store, persisting
        the issuer key so minted tickets stay verifiable across runs."""
        if self._broker is not None:
            if self._idstore is None:
                self._idstore = self._broker.identities
            self._attestor = self._broker.attestor
            self._audit = getattr(self._broker, "audit", None)
            self._quarantine = getattr(self._broker, "quarantine", None)
            return self._broker
        self._idstore = IdentityStore.from_dict(self.state.get(_IDSTORE_KEY, {}) or {})
        self._attestor = attest_mod.Attestor()           # C3: issuance requires attestation
        # C11: load the tamper-evident audit log + quarantine; verify the log against
        # its stored anchor and fail closed if an attacker rewrote it.
        self._audit_key = self.state.secret(self.m.project, "_audit", "key").encode("utf-8")
        self._audit = audit_mod.AuditLog.from_dict(self.state.get(_AUDIT_KEY, {}) or {})
        anchor = self.state.get(_AUDIT_ANCHOR_KEY)
        if anchor and not self._audit.verify_against(self._audit_key, anchor):
            raise ValueError("audit log failed its tamper check (chain or anchor mismatch)")
        self._quarantine = audit_mod.Quarantine.from_dict(self.state.get(_QUARANTINE_KEY, {}) or {})
        kp = self.state.get(_BROKER_KEY)
        issuer = None
        if kp:
            issuer = (kp["alg"], bytes.fromhex(kp["public"]), bytes.fromhex(kp["private"]))
        self._broker = broker_mod.Broker(self._idstore, issuer_keypair=issuer,
                                         attestor=self._attestor, audit=self._audit,
                                         quarantine=self._quarantine)
        if not kp:
            alg, pub, priv = self._broker.issuer_keypair()
            self.state.put(_BROKER_KEY, {"alg": alg, "public": pub.hex(), "private": priv.hex()})
        return self._broker

    def _ensure_dataplane(self):
        if self._dataplane is None:
            self._dataplane = dataplane_mod.DockerDataPlane(self.b)
        return self._dataplane

    def _check_supply_chain(self, svc: Service) -> None:
        """C12: refuse to run an image that violates the workload's pin/registry
        policy. No policy -> no-op. For a managed service the image comes from the
        catalog, not `svc.image`, so resolve it -- otherwise the policy would
        silently pass the catalog's mutable `:latest` images."""
        policy = svc.supply_chain_policy()
        if policy is None:
            return
        image = svc.image
        if image is None and svc.is_managed:
            image = catalog.spec_for(svc, self.m.project, self.state, self.m).image
        ok, reason = policy.check(image)
        if not ok:
            raise ValueError(f"supply-chain policy blocked {svc.name!r}: {reason}")

    def _admin_creds(self, dep: Service) -> "dict | None":
        """Admin creds a data plane needs to manage per-run users. Storage (MinIO)
        needs the root keys; postgres/cache authenticate locally and need none."""
        if dep.type == "storage":
            ex = catalog.exports_for(dep, self.m.project, self.state)
            return {"user": ex["S3_ACCESS_KEY"], "password": ex["S3_SECRET_KEY"]}
        return None

    def _admin_creds_from_state(self, service: str) -> "dict | None":
        """Recover a storage service's root keys straight from persisted state,
        for reaping after the service has been removed from the manifest. Reads
        (never generates) the slots catalog._storage stored."""
        u = self.state.get(f"{self.m.project}/{service}/user")
        p = self.state.get(f"{self.m.project}/{service}/password")
        return {"user": u, "password": p} if u and p else None

    def _reap_dataplane(self, dp, now: float) -> None:
        """Drop per-run credentials whose TTL has passed. A group whose reap fails
        is KEPT in state and retried next run, so a transient datastore outage can't
        orphan a role forever (cleanup is still best-effort: it never blocks apply)."""
        records = self.state.get(_DATAPLANE_KEY, []) or []
        survivors, expired = [], {}
        for rec in records:
            if rec.get("exp", 0) <= now:
                expired.setdefault((rec["stype"], rec["service"]), []).append(rec)
            else:
                survivors.append(rec)
        for (stype, service), recs in expired.items():
            dep = self.m.by_name().get(service)
            # For a removed service, recover admin creds from state so reaping
            # still works; if even that's gone, the records are unrecoverable.
            admin = self._admin_creds(dep) if dep is not None else self._admin_creds_from_state(service)
            unrecoverable = dep is None and stype == "storage" and admin is None
            try:
                dp.reap(self.m.project, stype, service, [r["cid"] for r in recs], admin=admin)
            except Exception:            # noqa: BLE001 -- keep for retry, don't block apply
                if not unrecoverable:    # else drop: retrying can never succeed
                    survivors.extend(recs)
        if expired:
            self.state.put(_DATAPLANE_KEY, survivors)

    def _brokered_binding_env(self, svc: Service, mint: bool = False) -> list[tuple[str, str]]:
        subject = identity_mod.subject_for(self.m.project, svc.name, svc.type)
        managed = [d for d in svc.bindings
                   if (dep := self.m.by_name().get(d)) and dep.is_managed]
        env: list[tuple[str, str]] = [("PERCH_IDENTITY_SUBJECT", subject)]
        if not mint:
            # plan()/drift() are read-only: don't issue identities or mint secrets.
            # Binding env doesn't affect source/config hashes, so this is enough.
            return env
        # Fail loud if two bindings would map to the same env var (e.g. "pg-main"
        # and "pg.main"), rather than silently dropping a credential.
        seen: dict[str, str] = {}
        for dep_name in managed:
            var = f"PERCH_CREDENTIAL_{_envname(dep_name)}"
            if var in seen:
                raise ValueError(
                    f"bindings {seen[var]!r} and {dep_name!r} both map to ${var}; "
                    f"rename one so credential env vars stay distinct")
            seen[var] = dep_name
        brk = self._ensure_broker()
        # Register what we expect this instance to be (C3) and present a matching
        # attestation: source/build identity, config, and the container host name.
        host = f"perch-{self.m.project}-{svc.name}"
        source_hash = svc.source_hash(self.b.fingerprint(svc))
        config_hash = svc.config_hash()
        self._attestor.expect(attest_mod.Expectation(subject, source_hash, config_hash, host))
        attestation = attest_mod.Attestation(subject, source_hash, config_hash, host)
        # Issue a fresh key for this run (rotation); store only the public record.
        # The reconciler is the principal here (it just generated the key in-process),
        # so reusing one challenge/proof across this workload's bindings is safe;
        # a cross-trust-boundary handshake with challenge consumption is C5/Phase B.
        principal = identity_mod.Principal(subject=subject, kind=svc.type,
                                           project=self.m.project, scopes=managed)
        issued = identity_mod.issue(principal)
        self._idstore.put(issued.identity)
        self.state.put(_IDSTORE_KEY, self._idstore.to_dict())
        challenge = identity_mod.new_challenge()
        proof = identity_mod.sign(issued.identity, issued.signing_key, challenge)
        dp = self._ensure_dataplane()
        # Two data-plane bindings of the same type would emit the same connection
        # env keys (e.g. two postgres -> two DATABASE_URLs); fail loud rather than
        # silently dropping one credential while still provisioning its role.
        dp_types: dict[str, str] = {}
        for dep_name in managed:
            dep = self.m.by_name()[dep_name]
            if dp.supports(dep.type):
                if dep.type in dp_types:
                    raise ValueError(
                        f"workload {svc.name!r} binds two {dep.type} services "
                        f"({dp_types[dep.type]!r}, {dep_name!r}); their per-run "
                        f"connection vars would collide -- bind at most one per type")
                dp_types[dep.type] = dep_name
        now = int(time.time())
        self._reap_dataplane(dp, now)
        for dep_name in managed:
            dep = self.m.by_name()[dep_name]
            # Authenticate + attest once per binding (the broker is the gate even
            # when the data plane mints the real credential).
            cred = brk.issue(subject, dep_name, challenge=challenge, proof=proof,
                             ttl=svc.identity_ttl, attestation=attestation)
            if dp.supports(dep.type):
                # C5/C6: redeem the ticket into a real, scoped, expiring credential
                # at the datastore, and inject THAT instead of the static password.
                grant = dataplane_mod.Grant(
                    project=self.m.project, service=dep_name, stype=dep.type,
                    access=svc.identity_access(dep_name), subject=subject,
                    ttl=int(cred.expires_at - cred.issued_at), nonce=secrets.token_hex(16),
                    issued_at=cred.issued_at, expires_at=cred.expires_at,
                    admin=self._admin_creds(dep),
                    buckets=list(dep.buckets) if dep.type == "storage" else None)
                creds_env, cid = dp.provision(grant)
                env += list(creds_env.items())
                self._record_dataplane_cred(grant.stype, grant.service, cid, grant.expires_at)
            else:
                # No identity-aware redemption yet -> hand over the capability ticket.
                env.append((f"PERCH_CREDENTIAL_{_envname(dep_name)}", cred.reference()))
        self._persist_detection()
        return env

    def _persist_detection(self) -> None:
        """C11: run the detector over the freshly-recorded audit events, quarantine
        flagged subjects, then bound + anchor + persist the log and quarantine."""
        if self._audit is None or self._audit_key is None:
            return
        for anomaly in audit_mod.Detector().scan(self._audit.events()):
            self._quarantine.add(anomaly.subject)
        self._audit = self._audit.truncated(_AUDIT_MAX_EVENTS)
        self._broker.audit = self._audit                 # keep the broker writing to the live log
        self.state.put(_QUARANTINE_KEY, self._quarantine.to_dict())
        self.state.put(_AUDIT_KEY, self._audit.to_dict())
        self.state.put(_AUDIT_ANCHOR_KEY, self._audit.anchor(self._audit_key))

    def _record_dataplane_cred(self, stype: str, service: str, cid: str, exp: int) -> None:
        records = self.state.get(_DATAPLANE_KEY, []) or []
        records.append({"stype": stype, "service": service, "cid": cid, "exp": int(exp)})
        self.state.put(_DATAPLANE_KEY, records)

    def _ctx(self, svc: Service, mint: bool = False) -> RenderContext:
        fp = self.b.fingerprint(svc)
        env = svc.resolved_env() + self._binding_env(svc, mint=mint)
        spec = None
        extra: list[str] = []
        if svc.is_managed:
            spec = catalog.spec_for(svc, self.m.project, self.state, self.m)
            # Managed services sit on both nets so egress-restricted workloads on
            # the internal network can still reach them (C8).
            net = egress_mod.main_network(self.m.project)
            extra = [egress_mod.internal_network(self.m.project)]
        else:
            mode, _ = svc.egress_policy
            net = egress_mod.network_for(self.m.project, svc.egress)
            if mode == "allow":
                # Bound managed services bypass the proxy (they're internal, not
                # internet hosts) so HTTP datastores stay reachable behind it.
                managed_hosts = [catalog.cname(self.m.project, d) for d in svc.bindings
                                 if (dep := self.m.by_name().get(d)) and dep.is_managed]
                env = env + list(egress_mod.proxy_env(self.m.project, svc.name, managed_hosts).items())
        return RenderContext(
            project=self.m.project, network=net,
            source_hash=svc.source_hash(fp), config_hash=svc.config_hash(),
            env=env, spec=spec, extra_networks=extra,
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
                self._check_supply_chain(svc)          # C12: deny before running
                mode, allow = svc.egress_policy
                if mode == "allow" and not svc.is_managed:
                    self.b.ensure_egress_proxy(self.m.project, svc.name, allow)
                self.b.converge(svc, self._ctx(svc, mint=True))
            elif a.kind == "restart":
                self.b.restart(self.m.project, a.target)
            elif a.kind == "prune":
                self.b.remove(self.m.project, a.target)
        # Keep managed services on the internal network so egress-restricted
        # workloads can reach them even if a managed container wasn't re-converged
        # this run (e.g. on first upgrade to C8). Idempotent.
        for svc in self.m.services:
            if svc.is_managed:
                self.b.attach_internal(self.m.project, svc.name)
        # Reap expired per-run credentials every apply, not only when a workload
        # reconverges -- otherwise Redis/MinIO users (no native expiry) accumulate.
        if self.state.get(_DATAPLANE_KEY):
            self._reap_dataplane(self._ensure_dataplane(), int(time.time()))

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
