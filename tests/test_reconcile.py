"""
Offline tests: a fake backend records calls so we can verify reconciler logic
without Docker. Run:  python tests/test_reconcile.py   (or pytest -q)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from perch.backend import LiveService  # noqa: E402
from perch.manifest import Build, EnvVar, Manifest, Route, Service  # noqa: E402
from perch.reconcile import Reconciler  # noqa: E402


class FakeBackend:
    def __init__(self, live=None):
        self._live = {ls.name: ls for ls in (live or [])}
        self.calls = []

    def ensure_network(self, project): return f"perch-{project}"
    def fingerprint(self, svc): return ""
    def list_managed(self, project): return list(self._live.values())
    def get(self, project, name): return self._live.get(name)
    def converge(self, svc, ctx):
        self.calls.append(("converge", svc.name))
        self._live[svc.name] = LiveService(svc.name, "running",
                                           ctx.source_hash, ctx.config_hash, health="none")
    def restart(self, project, name): self.calls.append(("restart", name))
    def remove(self, project, name): self.calls.append(("remove", name)); self._live.pop(name, None)
    def logs(self, project, name, follow=False): return iter(())
    def run_once(self, svc, ctx): self.calls.append(("run_once", svc.name)); return 0
    def exec(self, project, name, cmd): self.calls.append(("exec", name)); return 0


def svc(name, **kw):
    kw.setdefault("build", Build(context="./x"))
    return Service(name=name, **kw)


def test_new_service_creates():
    m = Manifest("p", [svc("web", port=8080)])
    kinds = [a.kind for a in Reconciler(FakeBackend(), m).plan()]
    assert kinds == ["create"]


def test_up_to_date_is_noop():
    s = svc("web", port=8080)
    live = LiveService("web", "running", s.source_hash(""), s.config_hash(), health="none")
    plan = Reconciler(FakeBackend([live]), Manifest("p", [s])).plan()
    assert [a.kind for a in plan] == ["noop"]


def test_source_change_rebuilds():
    s = svc("web", port=8080)
    live = LiveService("web", "running", "OLDHASH", s.config_hash(), health="none")
    plan = Reconciler(FakeBackend([live]), Manifest("p", [s])).plan()
    assert plan[0].kind == "rebuild"


def test_config_change_reconfigures():
    s = svc("web", port=8080, env=[EnvVar("A", "1")])
    live = LiveService("web", "running", s.source_hash(""), "OLDCONFIG", health="none")
    plan = Reconciler(FakeBackend([live]), Manifest("p", [s])).plan()
    assert plan[0].kind == "reconfigure"


def test_down_service_restarts():
    s = svc("web", port=8080)
    live = LiveService("web", "exited", s.source_hash(""), s.config_hash(), health="none")
    plan = Reconciler(FakeBackend([live]), Manifest("p", [s])).plan()
    assert plan[0].kind == "restart"


def test_force_rebuild():
    s = svc("web", port=8080)
    live = LiveService("web", "running", s.source_hash(""), s.config_hash(), health="none")
    plan = Reconciler(FakeBackend([live]), Manifest("p", [s]), force_rebuild=True).plan()
    assert plan[0].kind == "rebuild"


def test_secure_by_default():
    s = svc("web")
    assert s.security["read_only_rootfs"] and s.security["no_new_privileges"]
    assert s.security["drop_caps"] == ["ALL"] and s.security["user"] == "10001:10001"


def test_secret_resolution_and_hash_changes():
    os.environ["TOK"] = "a"
    s = svc("web", env=[EnvVar("T", "${TOK}", secret=True)])
    h1 = s.config_hash()
    os.environ["TOK"] = "b"
    assert s.config_hash() != h1  # rotation changes config hash -> recreate


def test_prune_removes_unmanaged():
    s = svc("keep")
    live = [LiveService("keep", "running", s.source_hash(""), s.config_hash(), health="none"),
            LiveService("stray", "running", "x", "y", health="none")]
    m = Manifest("p", [s], prune=True)
    plan = Reconciler(FakeBackend(live), m).plan()
    assert ("prune", "stray") in [(a.kind, a.target) for a in plan]


def test_drift_report():
    s = svc("wanted")
    live = [LiveService("stray", "running", "x", "y", health="unhealthy")]
    report = Reconciler(FakeBackend(live), Manifest("p", [s])).drift()
    assert any("MISSING" in r and "wanted" in r for r in report)
    assert any("UNMANAGED" in r and "stray" in r for r in report)


def test_apply_converges_and_prunes():
    s = svc("web", port=8080)
    fb = FakeBackend([LiveService("stray", "running", "x", "y", health="none")])
    Reconciler(fb, Manifest("p", [s], prune=True)).apply()
    assert ("converge", "web") in fb.calls and ("remove", "stray") in fb.calls


def test_cron_matcher():
    from datetime import datetime, timezone
    from perch.cli import cron_matches
    t = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert cron_matches("0 12 * * *", t)
    assert cron_matches("*/6 * * * *", datetime(2026, 1, 1, 0, 6, tzinfo=timezone.utc))
    assert not cron_matches("30 9 * * *", t)


# ---- managed services (Phase 0/1) ---------------------------------------
import tempfile  # noqa: E402
from perch import catalog, backups  # noqa: E402
from perch.state import State  # noqa: E402


def _state():
    return State(tempfile.mkdtemp())


def pg(name="db", **kw):
    return Service(name=name, type="postgres", extensions=["pgvector"], **kw)


def test_managed_postgres_plans_create():
    m = Manifest("p", [pg("db")])
    plan = Reconciler(FakeBackend(), m, state=_state()).plan()
    assert [a.kind for a in plan] == ["create"]


def test_catalog_postgres_spec():
    st = _state()
    m = Manifest("p", [pg("db")])
    spec = catalog.spec_for(m.services[0], "p", st, m)
    assert spec.image.startswith("pgvector/pgvector:pg")
    assert spec.internal_port == 5432
    assert spec.security["read_only_rootfs"] is False
    assert spec.security["drop_caps"] == ["ALL"]
    assert spec.init_sql and "vector" in spec.init_sql


def test_binding_env_injected():
    st = _state()
    web = svc("web", port=8080, bindings=["db"])
    m = Manifest("p", [pg("db"), web])
    env = dict(Reconciler(FakeBackend(), m, state=st)._ctx(web).env)
    assert env["PGHOST"] == "perch-p-db"
    assert env["DATABASE_URL"].startswith("postgresql://app:")


def test_deploy_order_managed_before_consumer():
    web = svc("web", port=8080, bindings=["db"])
    m = Manifest("p", [web, pg("db")])
    order = [s.name for s in m.deploy_order()]
    assert order.index("db") < order.index("web")


def test_rest_api_requires_postgres():
    st = _state()
    api = Service(name="api", type="rest-api", database="db")
    m = Manifest("p", [pg("db"), api])
    spec = catalog.spec_for(api, "p", st, m)
    assert dict(spec.env)["PGRST_DB_URI"].startswith("postgresql://app:")
    bad = Service(name="api2", type="rest-api")
    try:
        catalog.spec_for(bad, "p", st, Manifest("p", [bad]))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_state_secret_is_stable():
    st = _state()
    a = st.secret("p", "db", "password")
    assert st.secret("p", "db", "password") == a
    assert st.secret("p", "db", "other") != a


def test_managed_source_hash_tracks_version():
    assert pg("db", version="16").source_hash() != pg("db", version="17").source_hash()


def test_backup_retention():
    root = tempfile.mkdtemp()
    d = backups.backup_dir(root, "p", "db")
    d.mkdir(parents=True)
    for ts in ["20260101T000000Z", "20260102T000000Z", "20260103T000000Z"]:
        (d / f"{ts}.sql.gz").write_bytes(b"x")
    kept = backups.prune(root, "p", "db", retain=2)
    assert sorted(f.name for f in kept) == ["20260102T000000Z.sql.gz", "20260103T000000Z.sql.gz"]
    assert not (d / "20260101T000000Z.sql.gz").exists()


# ---- auth + functions + API (frontend integration) ----------------------
def test_function_is_workload_and_builds():
    fn = Service(name="hook", type="function", runtime="python312", build=Build(context="./fn"), port=8080)
    assert fn.is_managed is False
    plan = Reconciler(FakeBackend(), Manifest("p", [fn]), state=_state()).plan()
    assert [a.kind for a in plan] == ["create"]


def test_auth_spec_wires_database():
    st = _state()
    auth = Service(name="identity", type="auth", database="db")
    m = Manifest("p", [pg("db"), auth])
    assert auth.is_managed is True
    spec = catalog.spec_for(auth, "p", st, m)
    e = dict(spec.env)
    assert spec.image.startswith("ghcr.io/zitadel/zitadel")
    assert e["ZITADEL_DATABASE_POSTGRES_HOST"] == "perch-p-db"
    assert len(e["ZITADEL_MASTERKEY"]) == 32
    # auth depends on its database in deploy order
    assert "db" in m.deps(auth)


def test_auth_requires_postgres():
    st = _state()
    bad = Service(name="identity", type="auth")
    try:
        catalog.spec_for(bad, "p", st, Manifest("p", [bad]))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_api_services_and_masking():
    from perch.api import PerchAPI, MASK
    st = _state()
    web = svc("web", port=8080, bindings=["db"],
              env=[EnvVar("GREETING", "hi"), EnvVar("TOKEN", "secret", secret=True)])
    m = Manifest("p", [pg("db"), web])
    api = PerchAPI(m, backend=FakeBackend(), state=st)
    svcs = {s["name"]: s for s in api.services()}
    assert svcs["web"]["bindings"] == ["db"]
    env = {e["key"]: e["value"] for e in svcs["web"]["env"]}
    assert env["GREETING"] == "hi" and env["TOKEN"] == MASK   # secret masked
    # managed-service exports mask credentials
    detail = api.service("db")
    assert detail["exports"]["PGPASSWORD"] == MASK
    assert detail["exports"]["PGHOST"] == "set"
    assert detail["bound_by"] == ["web"]


def test_api_topology_edges():
    from perch.api import PerchAPI
    web = svc("web", port=8080, bindings=["db"])
    m = Manifest("p", [pg("db"), web])
    topo = PerchAPI(m, backend=FakeBackend(), state=_state()).topology()
    names = {n["name"] for n in topo["nodes"]}
    assert names == {"db", "web"}
    assert {"from": "web", "to": "db"} in topo["edges"]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")
