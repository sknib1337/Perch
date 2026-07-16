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
    def ensure_egress_proxy(self, project, service, allow_hosts):
        self.calls.append(("egress_proxy", service, list(allow_hosts)))
    def ensure_mcp_gateway(self, project, service, image, config, host_spool_dir):
        self.calls.append(("mcp_gateway", service, image, config))
    def attach_internal(self, project, name):
        self.calls.append(("attach_internal", name))
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


# ---- C2: per-agent cryptographic identity (perch/identity.py) -----------
from perch import identity as idmod  # noqa: E402


def _principal(name="agent", scopes=("db",)):
    return idmod.Principal(subject=idmod.subject_for("p", name, "agent"),
                           kind="agent", project="p", scopes=list(scopes))


def test_identity_roundtrip_and_tamper():
    # Exhaustively cover every signing backend available in this install.
    for signer in idmod.available_signers():
        issued = idmod.issue(_principal(), signer=signer)
        ident, key = issued.identity, issued.signing_key
        challenge = idmod.new_challenge()
        sig = idmod.sign(ident, key, challenge)
        assert idmod.verify(ident, challenge, sig), f"{signer.alg} should verify"
        # tampered signature is rejected
        bad = bytearray(sig); bad[0] ^= 0xFF
        assert not idmod.verify(ident, challenge, bytes(bad)), f"{signer.alg} tamper-sig"
        # signature over a different challenge is rejected
        assert not idmod.verify(ident, idmod.new_challenge(), sig), f"{signer.alg} wrong-challenge"
        # a different identity's key does not validate
        other = idmod.issue(_principal("other"), signer=signer)
        assert not idmod.verify(other.identity, challenge, sig), f"{signer.alg} wrong-identity"


def test_identity_default_signer_roundtrips():
    issued = idmod.issue(_principal())
    c = idmod.new_challenge()
    assert idmod.verify(issued.identity, c, idmod.sign(issued.identity, issued.signing_key, c))


def test_identity_public_key_secrecy_flag():
    # HMAC verification material is the shared secret; Ed25519's is a real pubkey.
    hmac_id = idmod.issue(_principal(), signer=idmod.HmacSigner()).identity
    assert hmac_id.public_key_is_secret is True
    assert hmac_id.redacted()["public_key"] == "<sealed>"
    if idmod._HAVE_ED25519:
        ed_id = idmod.issue(_principal(), signer=idmod.Ed25519Signer()).identity
        assert ed_id.public_key_is_secret is False
        assert ed_id.redacted()["public_key"] == ed_id.public_key


def test_identity_subject_is_stable():
    assert idmod.subject_for("p", "web") == idmod.subject_for("p", "web")
    assert idmod.subject_for("p", "web") != idmod.subject_for("p", "api")


def test_identity_serialization_roundtrip():
    ident = idmod.issue(_principal(scopes=("db", "cache"))).identity
    back = idmod.Identity.from_dict(ident.to_dict())
    assert back == ident


def test_identity_unknown_alg_raises():
    ident = idmod.issue(_principal()).identity
    bogus = idmod.Identity.from_dict({**ident.to_dict(), "alg": "rot13"})
    try:
        idmod.verify(bogus, idmod.new_challenge(), b"x")
        assert False, "expected UnknownAlgorithm"
    except idmod.UnknownAlgorithm:
        pass
    # an unhashable alg must also fail loud as UnknownAlgorithm, not crash
    weird = idmod.Identity.from_dict(ident.to_dict()); weird.alg = ["hmac-sha256"]
    try:
        idmod.verify(weird, b"c", b"s"); assert False, "expected UnknownAlgorithm"
    except idmod.UnknownAlgorithm:
        pass


def test_identity_store_verifies_by_subject():
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal("agent")))
    subject = issued.identity.subject
    c = idmod.new_challenge()
    sig = idmod.sign(issued.identity, issued.signing_key, c)
    assert store.verify(subject, c, sig)
    assert not store.verify("perch://p/agent/ghost", c, sig)   # unknown subject -> closed
    assert not store.verify(subject, idmod.new_challenge(), sig)  # wrong challenge


def test_identity_no_alg_downgrade_via_store():
    # The Ed25519->HMAC downgrade: an attacker who knows only the published
    # public key forges an HMAC tag over it. The store verifies against the
    # TRUSTED stored record (alg=ed25519), so the forgery is rejected.
    if not idmod._HAVE_ED25519:
        return
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal(), signer=idmod.Ed25519Signer()))
    subject, c = issued.identity.subject, idmod.new_challenge()
    pub = bytes.fromhex(issued.identity.public_key)
    import hashlib as _h, hmac as _hm
    forged_plain = _hm.new(pub, c, _h.sha256).digest()
    forged_domain = _hm.new(pub, b"hmac-sha256\x00" + c, _h.sha256).digest()
    assert not store.verify(subject, c, forged_plain)
    assert not store.verify(subject, c, forged_domain)


def test_identity_short_hmac_key_fails_closed():
    # A degenerate/empty HMAC verification key must never validate.
    import hashlib as _h, hmac as _hm
    for pk in ("", "00"):
        ident = idmod.Identity(subject="s", kind="agent", project="p", scopes=[],
                               alg=idmod.HMAC_ALG, public_key=pk, created_at=0)
        forged = _hm.new(bytes.fromhex(pk), b"hmac-sha256\x00c", _h.sha256).digest()
        assert not idmod.verify(ident, b"c", forged)


def test_identity_repr_redacts_secrets():
    issued = idmod.issue(_principal(), signer=idmod.HmacSigner())
    secret_hex = issued.identity.public_key
    assert secret_hex not in repr(issued.identity)        # HMAC secret not in repr
    assert "<sealed>" in repr(issued.identity)
    assert secret_hex not in repr(issued)                 # nor via IssuedIdentity
    assert issued.signing_key.hex() not in repr(issued)   # private key never rendered


# ---- C1: short-lived scoped credential broker (perch/broker.py) ---------
from perch import broker as brkmod  # noqa: E402
from perch.dataplane import FakeDataPlane  # noqa: E402


def _broker(scopes=("db",), clock=None):
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal("agent", scopes)))
    brk = brkmod.Broker(store, **({"clock": clock} if clock else {}))
    return brk, issued


def _proof(issued):
    c = idmod.new_challenge()
    return c, idmod.sign(issued.identity, issued.signing_key, c)


def test_broker_issues_scoped_credential():
    brk, issued = _broker(scopes=("db",))
    sub = issued.identity.subject
    c, p = _proof(issued)
    cred = brk.issue(sub, "db", challenge=c, proof=p)
    assert cred.resource == "db" and cred.token
    assert brk.authorize(cred.token, "db")
    assert not brk.authorize(cred.token, "cache")        # wrong resource
    # requesting a resource the principal is not scoped for is denied (fail closed)
    c2, p2 = _proof(issued)
    try:
        brk.issue(sub, "cache", challenge=c2, proof=p2); assert False, "expected deny"
    except brkmod.BrokerDenied:
        pass


def test_broker_rejects_unverified_identity():
    brk, issued = _broker()
    sub = issued.identity.subject
    # forged proof
    try:
        brk.issue(sub, "db", challenge=idmod.new_challenge(), proof=b"\x00" * 64)
        assert False, "expected deny"
    except brkmod.BrokerDenied:
        pass
    # unknown subject
    c, p = _proof(issued)
    try:
        brk.issue("perch://p/agent/ghost", "db", challenge=c, proof=p)
        assert False, "expected deny"
    except brkmod.BrokerDenied:
        pass


def test_broker_ttl_expiry():
    now = [1000.0]
    brk, issued = _broker(clock=lambda: now[0])
    c, p = _proof(issued)
    cred = brk.issue(issued.identity.subject, "db", challenge=c, proof=p, ttl=1)
    assert brk.authorize(cred.token, "db")               # valid at issue time
    now[0] += 2
    assert not brk.authorize(cred.token, "db")           # expired -> denied
    assert brk.verify_token(cred.token) is None
    assert cred.is_expired(now[0])


def test_broker_token_tamper_and_foreign_issuer():
    brk, issued = _broker()
    c, p = _proof(issued)
    cred = brk.issue(issued.identity.subject, "db", challenge=c, proof=p)
    payload, sig = cred.token.split(".", 1)
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert brk.verify_token(payload + "." + flipped) is None     # bad signature
    assert brk.verify_token("not-a-token") is None
    other, _ = _broker()                                          # different issuer key
    assert other.verify_token(cred.token) is None


def test_broker_scope_in_credential():
    brk, issued = _broker()
    c, p = _proof(issued)
    cred = brk.issue(issued.identity.subject, "db", challenge=c, proof=p,
                     scopes=["postgres:read"])
    assert brk.authorize(cred.token, "db", "postgres:read")
    assert not brk.authorize(cred.token, "db", "postgres:write")


def test_broker_ttl_is_bounded_and_validated():
    brk, issued = _broker()
    sub = issued.identity.subject
    # over the hard ceiling, zero/negative, and non-numeric all fail closed
    for bad in (brkmod.MAX_TTL + 1, 0, -5, "15m", True, [60]):
        c, p = _proof(issued)
        try:
            brk.issue(sub, "db", challenge=c, proof=p, ttl=bad)
            assert False, f"expected deny for ttl={bad!r}"
        except brkmod.BrokerDenied:
            pass
    # a sane TTL still works
    c, p = _proof(issued)
    assert brk.issue(sub, "db", challenge=c, proof=p, ttl=brkmod.MAX_TTL).token
    # the broker's own default TTL is bounded too
    try:
        brkmod.Broker(idmod.IdentityStore(), default_ttl=brkmod.MAX_TTL + 1)
        assert False, "expected deny for oversized default_ttl"
    except brkmod.BrokerDenied:
        pass


def test_broker_hmac_issuer_has_no_exportable_pubkey():
    store = idmod.IdentityStore()
    brk = brkmod.Broker(store, alg=idmod.HMAC_ALG)
    try:
        brk.issuer_public(); assert False, "HMAC must not export a verify key"
    except brkmod.BrokerDenied:
        pass
    if idmod._HAVE_ED25519:                       # Ed25519 issuer CAN export a pubkey
        ed = brkmod.Broker(idmod.IdentityStore(), alg=idmod.ED25519_ALG)
        alg, pub = ed.issuer_public()
        assert alg == idmod.ED25519_ALG and pub


def test_identity_proof_not_replayable_as_broker_ticket():
    # Purpose domain separation: an identity proof signed by a key must not pass
    # as a broker ticket, even if an attacker could line up the keys.
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal("agent", ("db",))))
    c = idmod.new_challenge()
    proof = idmod.sign(issued.identity, issued.signing_key, c)
    # craft a "token" whose signature is actually an identity proof
    import base64 as _b64
    fake = _b64.urlsafe_b64encode(c).rstrip(b"=").decode() + "." + \
        _b64.urlsafe_b64encode(proof).rstrip(b"=").decode()
    brk = brkmod.Broker(store)
    assert brk.verify_token(fake) is None


def test_broker_envvar_collision_is_rejected():
    # Two bindings normalizing to the same env var must fail loud, not drop one.
    a = svc("worker", type="agent", bindings=["pg-main", "pg.main"])
    a.identity = True
    m = Manifest("p", [pg("pg-main"), pg("pg.main"), a])
    rec = Reconciler(FakeBackend(), m, state=_state())
    try:
        rec._ctx(a, mint=True)
        assert False, "expected collision error"
    except ValueError as e:
        assert "PERCH_CREDENTIAL_PG_MAIN" in str(e)


# ---- C1 integration: bindings seam routes through the broker -------------
def _agent_with_db(identity=True):
    a = svc("worker", type="agent", bindings=["db"])
    a.identity = identity
    return Manifest("p", [pg("db"), a]), a


def test_identity_postgres_redeems_into_per_run_credential():
    # C5: an identity-enabled postgres binding gets a real but ephemeral per-run
    # credential from the data plane -- not a ticket, and not the static password.
    m, agent = _agent_with_db()
    fdp = FakeDataPlane()
    rec = Reconciler(FakeBackend(), m, state=_state(), dataplane=fdp)
    # read-only (plan/drift): no minting, no provisioning
    ro = dict(rec._binding_env(agent, mint=False))
    assert ro.get("PERCH_IDENTITY_SUBJECT") and not fdp.provisioned
    assert "DATABASE_URL" not in ro
    # converge/run (mint): real per-run credential injected
    env = dict(rec._ctx(agent, mint=True).env)
    assert "perch_run_" in env["DATABASE_URL"]         # per-run role, not 'app'
    assert "PERCH_CREDENTIAL_DB" not in env            # ticket redeemed, not handed over
    g = fdp.provisioned[0]
    assert g.service == "db" and g.stype == "postgres" and g.access == "write"


def test_identity_unsupported_binding_falls_back_to_ticket():
    # A binding the data plane can't redeem yet still gets the Phase-A ticket.
    m, agent = _agent_with_db()
    rec = Reconciler(FakeBackend(), m, state=_state(), dataplane=FakeDataPlane(supported=()))
    env = dict(rec._ctx(agent, mint=True).env)
    assert "PERCH_CREDENTIAL_DB" in env
    assert rec._ensure_broker().authorize(env["PERCH_CREDENTIAL_DB"], "db")


def test_identity_read_scope_narrows_access():
    m, agent = _agent_with_db()
    agent.identity = {"scopes": {"db": "read"}}
    fdp = FakeDataPlane()
    Reconciler(FakeBackend(), m, state=_state(), dataplane=fdp)._ctx(agent, mint=True)
    assert fdp.provisioned[0].access == "read"


def test_identity_expired_creds_are_reaped():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    st = State(root)
    st.put("_dataplane", [{"stype": "postgres", "service": "db", "cid": "perch_run_old", "exp": 0}])
    m, agent = _agent_with_db()
    fdp = FakeDataPlane()
    Reconciler(FakeBackend(), m, state=st, dataplane=fdp)._ctx(agent, mint=True)
    assert ("postgres", "db", ["perch_run_old"]) in fdp.reaped     # expired role dropped


def test_reap_keeps_records_when_reap_fails():
    import tempfile
    from perch.state import State

    class FailingDataPlane(FakeDataPlane):
        def reap(self, *a):
            raise RuntimeError("datastore down")

    root = tempfile.mkdtemp()
    st = State(root)
    st.put("_dataplane", [{"stype": "postgres", "service": "db", "cid": "perch_run_old", "exp": 0}])
    m, agent = _agent_with_db()
    Reconciler(FakeBackend(), m, state=st, dataplane=FailingDataPlane())._ctx(agent, mint=True)
    # a failed reap must NOT drop the record -- it's retried next run
    assert "perch_run_old" in [r["cid"] for r in st.get("_dataplane")]


def test_identity_two_postgres_bindings_rejected():
    a = svc("worker", type="agent", bindings=["db1", "db2"])
    a.identity = True
    m = Manifest("p", [pg("db1"), pg("db2"), a])
    rec = Reconciler(FakeBackend(), m, state=_state(), dataplane=FakeDataPlane())
    try:
        rec._ctx(a, mint=True); assert False, "two postgres bindings must be rejected"
    except ValueError as e:
        assert "at most one per type" in str(e)


def test_static_binding_path_preserved_without_identity():
    m, _ = _agent_with_db(identity=None)            # identity off -> today's behavior
    web = m.by_name()["worker"]
    env = dict(Reconciler(FakeBackend(), m, state=_state())._ctx(web, mint=True).env)
    assert env["DATABASE_URL"].startswith("postgresql://app:")   # static path intact
    assert "PERCH_CREDENTIAL_DB" not in env


def test_identity_optin_is_backwards_compatible():
    base = svc("web", port=8080, bindings=["db"])
    assert not base.identity_enabled
    same = svc("web", port=8080, bindings=["db"]); same.identity = None
    assert same.config_hash() == base.config_hash()             # absence == unchanged hash
    on = svc("web", port=8080, bindings=["db"]); on.identity = True
    assert on.config_hash() != base.config_hash()               # enabling = real change


def test_broker_issuer_key_persists_across_reconcilers():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    m, agent = _agent_with_db()
    rec = Reconciler(FakeBackend(), m, state=State(root), dataplane=FakeDataPlane())
    rec._ctx(agent, mint=True)                       # creates + persists the issuer key
    kp1 = rec._ensure_broker().issuer_keypair()
    # a fresh reconciler over the same state reloads the identical issuer key
    rec2 = Reconciler(FakeBackend(), m, state=State(root), dataplane=FakeDataPlane())
    assert rec2._ensure_broker().issuer_keypair() == kp1


# ---- C3: attestation before issuance (perch/attest.py) ------------------
from perch import attest as atmod  # noqa: E402


def test_attest_accept_and_deny():
    exp = atmod.Expectation("sub", "srchash", "cfghash", "perch-p-worker")
    at = atmod.Attestor([exp])
    assert at.verify(atmod.Attestation("sub", "srchash", "cfghash", "perch-p-worker"))
    # any single field mismatch is denied (swapped image, drifted config, wrong host)
    assert not at.verify(atmod.Attestation("sub", "WRONG", "cfghash", "perch-p-worker"))
    assert not at.verify(atmod.Attestation("sub", "srchash", "WRONG", "perch-p-worker"))
    assert not at.verify(atmod.Attestation("sub", "srchash", "cfghash", "WRONG"))
    # unknown subject -> closed
    assert not at.verify(atmod.Attestation("other", "srchash", "cfghash", "perch-p-worker"))


def test_broker_requires_attestation_when_configured():
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal("agent", ("db",))))
    sub = issued.identity.subject
    at = atmod.Attestor([atmod.Expectation(sub, "s", "c", "perch-p-agent")])
    brk = brkmod.Broker(store, attestor=at)
    good = atmod.Attestation(sub, "s", "c", "perch-p-agent")

    def fresh():
        return _proof(issued)

    # missing attestation -> deny
    c, p = fresh()
    try:
        brk.issue(sub, "db", challenge=c, proof=p); assert False, "need attestation"
    except brkmod.BrokerDenied:
        pass
    # matching attestation -> issued
    c, p = fresh()
    assert brk.issue(sub, "db", challenge=c, proof=p, attestation=good).token
    # mismatched attestation (wrong config) -> deny
    c, p = fresh()
    bad = atmod.Attestation(sub, "s", "TAMPERED", "perch-p-agent")
    try:
        brk.issue(sub, "db", challenge=c, proof=p, attestation=bad); assert False
    except brkmod.BrokerDenied:
        pass
    # attestation for a different subject than the requester -> deny
    c, p = fresh()
    other = atmod.Attestation("perch://p/agent/other", "s", "c", "perch-p-agent")
    try:
        brk.issue(sub, "db", challenge=c, proof=p, attestation=other); assert False
    except brkmod.BrokerDenied:
        pass


def test_attestation_enforced_in_identity_path():
    m, agent = _agent_with_db()
    rec = Reconciler(FakeBackend(), m, state=_state(), dataplane=FakeDataPlane())
    # minting succeeds only because a matching self-attestation was presented;
    # the broker is configured with an attestor, so an absent/bad one would deny.
    env = dict(rec._ctx(agent, mint=True).env)
    assert "DATABASE_URL" in env
    sub = env["PERCH_IDENTITY_SUBJECT"]
    assert rec._attestor is not None and sub in rec._attestor


# ---- C4: sealed secrets at rest (perch/crypto.py + state.py) -------------
from pathlib import Path  # noqa: E402

from perch import crypto as cryptomod  # noqa: E402


def _sealers():
    """Every sealing scheme available in this install (stdlib always; +Fernet)."""
    key = b"unit-test-master-key-0123456789ab"
    out = [cryptomod.Sealer(key, prefer_fernet=False)]          # PSL1 (stdlib)
    if cryptomod._HAVE_FERNET:
        out.append(cryptomod.Sealer(key, prefer_fernet=True))   # PSF1 (Fernet)
    return out


def test_seal_roundtrip_and_tamper():
    for s in _sealers():
        for pt in (b"", b"hunter2", b"\x00\x01\x02 binary \xff", "DATABASE_URL=secret".encode()):
            token = s.seal(pt)
            assert cryptomod.is_sealed(token)
            assert s.unseal(token) == pt                         # round-trip
        token = s.seal(b"sensitive-credential")
        # flip one base64 char in the body -> authentication must fail (no plaintext).
        # Condition on body[0] (the char being replaced): conditioning on any other
        # char makes the "tamper" a no-op whenever the body already starts with "A",
        # which made this test flake roughly 1 run in 64.
        scheme, _, body = token.partition(".")
        bad = scheme + "." + (("A" if body[0] != "A" else "B") + body[1:])
        assert bad != token                                  # the tamper must be real
        try:
            s.unseal(bad); assert False, "tamper must be rejected"
        except cryptomod.SealError:
            pass


def test_seal_wrong_key_and_unknown_scheme_fail_closed():
    token = cryptomod.Sealer(b"key-A-0123456789abcdef0123456789").seal(b"secret")
    try:
        cryptomod.Sealer(b"key-B-0123456789abcdef0123456789").unseal(token)
        assert False, "wrong key must fail"
    except cryptomod.SealError:
        pass
    try:
        cryptomod.Sealer(b"k" * 32).unseal("NOPE.deadbeef"); assert False
    except cryptomod.SealError:
        pass


def test_state_ciphertext_at_rest_and_roundtrip():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    sealer = cryptomod.Sealer(b"state-master-key-0123456789abcdef")
    st = State(root, sealer=sealer)
    pw = st.secret("p", "db", "password")
    st.put("_broker/issuer", {"alg": "ed25519", "private": "deadbeef"})
    # on disk: ciphertext with a scheme tag, NOT the secret material
    raw = (Path(root) / "state.json").read_text()
    assert cryptomod.is_sealed(raw)
    assert pw not in raw and "deadbeef" not in raw and "_broker/issuer" not in raw
    # a new State with the same key reads the same values back
    st2 = State(root, sealer=cryptomod.Sealer(b"state-master-key-0123456789abcdef"))
    assert st2.secret("p", "db", "password") == pw
    assert st2.get("_broker/issuer")["private"] == "deadbeef"


def test_state_plaintext_without_key_unchanged():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    st = State(root, sealer=None)                  # no key -> prior behavior
    pw = st.secret("p", "db", "password")
    raw = (Path(root) / "state.json").read_text()
    assert not cryptomod.is_sealed(raw)
    assert pw in raw                               # cleartext on disk, exactly as before


def test_sealed_state_without_key_fails_loud():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    State(root, sealer=cryptomod.Sealer(b"k" * 32)).secret("p", "db", "password")
    try:
        State(root, sealer=None)                   # sealed file, no key -> must not wipe
        assert False, "expected SealError, not silent reset"
    except cryptomod.SealError:
        pass


def test_seal_rejects_weak_master_key():
    for weak in (b"", b"short", b"0123456789abcde"):    # empty and < 16 bytes
        try:
            cryptomod.Sealer(weak); assert False, f"weak key {weak!r} must be rejected"
        except cryptomod.SealError:
            pass
    assert cryptomod.Sealer(b"0123456789abcdef")        # exactly 16 bytes is OK


def test_state_corrupt_cleartext_fails_loud():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    p = Path(root) / "state.json"
    p.write_text("{ this is not valid json")            # non-empty, unparseable
    try:
        State(root, sealer=None); assert False, "corrupt state must not be silently wiped"
    except cryptomod.SealError:
        pass
    # an empty/whitespace file is still treated as empty state (not an error)
    p.write_text("   \n")
    assert State(root, sealer=None).secret("p", "db", "k")  # constructs fine


def test_state_lazy_migration_to_sealed():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    plain = State(root, sealer=None)
    pw = plain.secret("p", "db", "password")
    assert pw in (Path(root) / "state.json").read_text()        # starts cleartext
    sealer = cryptomod.Sealer(b"migrate-master-key-0123456789ab")
    migrated = State(root, sealer=sealer)                        # read legacy cleartext
    migrated.put("touch", 1)                                     # next write seals it
    raw = (Path(root) / "state.json").read_text()
    assert cryptomod.is_sealed(raw) and pw not in raw
    assert migrated.secret("p", "db", "password") == pw         # value preserved


# ---- C7: authenticated control plane (perch/api.py) ---------------------
from perch import api as apimod  # noqa: E402


def test_auth_disabled_allows_everything():
    pol = apimod.AuthPolicy(require=False)            # default: today's behavior
    assert pol.check("GET", "/api/services", None) == 200
    assert pol.check("POST", "/api/apply", None) == 200


def test_auth_401_403_200_matrix():
    pol = apimod.AuthPolicy({"ADM": "admin", "VW": "viewer"}, require=True)
    # unauthenticated reads/writes -> 401
    assert pol.check("GET", "/api/services", None) == 401
    assert pol.check("GET", "/api/services", "wrong") == 401
    assert pol.check("POST", "/api/apply", None) == 401
    # viewer: may read, may not write -> 403
    assert pol.check("GET", "/api/services", "VW") == 200
    assert pol.check("POST", "/api/apply", "VW") == 403
    # admin: full access
    assert pol.check("GET", "/api/services", "ADM") == 200
    assert pol.check("POST", "/api/apply", "ADM") == 200
    # static console assets stay public even with auth on
    assert pol.check("GET", "/", None) == 200
    assert pol.check("GET", "/app.js", None) == 200


def test_api_token_parsing_and_loading():
    assert apimod._parse_tokens("a:admin, b:viewer ,c") == {"a": "admin", "b": "viewer", "c": "admin"}
    import tempfile
    toks = apimod.load_api_tokens(root=tempfile.mkdtemp(), env={"PERCH_API_TOKENS": "x:viewer"})
    assert toks == {"x": "viewer"}


def test_auth_token_validation_fails_closed():
    # empty role after a colon must NOT silently become admin
    assert apimod._parse_tokens("tok:") == {}
    # unknown role is skipped, not granted
    assert apimod._parse_tokens("tok:superuser") == {}
    # a bare token (no colon) still defaults to admin (documented)
    assert apimod._parse_tokens("solo") == {"solo": "admin"}
    # well-formed entries still parse, role case-normalized
    assert apimod._parse_tokens("a:ADMIN, b:viewer") == {"a": "admin", "b": "viewer"}


def test_auth_non_ascii_token_is_clean_401_not_500():
    pol = apimod.AuthPolicy({"ADM": "admin"}, require=True)
    assert pol.role_for("tokén") is None                 # no TypeError/crash
    assert pol.check("GET", "/api/services", "café") == 401


def test_load_api_tokens_json_normalizes_and_skips_unknown():
    import json as _json, tempfile
    root = tempfile.mkdtemp()
    (Path(root) / "api_tokens.json").write_text(_json.dumps({"good": "Admin", "bad": "root"}))
    assert apimod.load_api_tokens(root=root, env={}) == {"good": "admin"}   # bad role dropped


def test_auth_enforced_through_http_handler():
    # Drive the real handler with a fake request to confirm the gate is wired.
    import io
    web = svc("web", port=8080)
    api = apimod.PerchAPI(Manifest("p", [web]), backend=FakeBackend(), state=_state())
    policy = apimod.AuthPolicy({"ADM": "admin"}, require=True)
    Handler = apimod.make_handler(api, policy)

    def request(method, path, token=None):
        captured = {}

        class FakeHandler(Handler):
            def __init__(self):                       # bypass socket setup
                self.headers = {"Authorization": f"Bearer {token}"} if token else {}
                self.command, self.path = method, path
                self.wfile = io.BytesIO()
            def send_response(self, code, *a): captured["code"] = code
            def send_header(self, *a): pass
            def end_headers(self): pass
        h = FakeHandler()
        h.do_POST() if method == "POST" else h.do_GET()
        return captured.get("code")

    assert request("GET", "/api/services") == 401           # no token
    assert request("POST", "/api/apply", "ADM") == 200      # admin write ok
    assert request("GET", "/api/services", "ADM") == 200     # admin read ok
    assert request("GET", "/index.html") == 200             # static is public


# ---- C5/C6: identity-aware data plane (perch/dataplane.py) ---------------
from perch import dataplane as dpmod  # noqa: E402


def test_pg_provision_sql_scopes_read_vs_write():
    role = dpmod.pg_role_name("abc123")
    assert role == "perch_run_abc123"
    read = dpmod.pg_provision_sql(role, "pw", "read", 900)
    write = dpmod.pg_provision_sql(role, "pw", "write", 900)
    # both create a non-inheriting login role expiring on the SERVER clock
    for sql in (read, write):
        assert "CREATE ROLE perch_run_abc123 LOGIN NOINHERIT" in sql
        assert "make_interval(secs => 900)" in sql and "VALID UNTIL %L" in sql
        assert "GRANT SELECT ON ALL TABLES" in sql
    # only write grants mutation; read must not
    assert "INSERT, UPDATE, DELETE" not in read
    assert "INSERT, UPDATE, DELETE" in write


def test_pg_provision_sql_escapes_password_quote():
    sql = dpmod.pg_provision_sql("perch_run_x", "a'b", "read", 900)
    assert "PASSWORD 'a''b'" in sql                       # single quote doubled


def test_pg_reap_expired_sql_targets_only_expired():
    sql = dpmod.pg_reap_expired_sql()
    assert "rolvaliduntil < now()" in sql                 # server decides what's expired
    assert "DROP OWNED BY" in sql and "DROP ROLE" in sql
    assert "perch\\_run\\_%" in sql                       # only Perch per-run roles


def test_postgres_bootstrap_revokes_public_execute():
    spec = catalog.spec_for(pg("db"), "p", _state(), Manifest("p", [pg("db")]))
    assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC" in spec.init_sql


def test_pg_connection_env_uses_per_run_role():
    env = dpmod.pg_connection_env("p", "db", "perch_run_x", "secret")
    assert env["PGUSER"] == "perch_run_x"
    assert env["DATABASE_URL"] == "postgresql://perch_run_x:secret@perch-p-db:5432/app"


def test_docker_dataplane_supports_all_datastores():
    dp = dpmod.DockerDataPlane(FakeBackend())
    assert dp.supports("postgres") and dp.supports("cache") and dp.supports("storage")
    assert not dp.supports("webapp")


def test_redis_acl_setuser_scopes_read_vs_write():
    read = dpmod.redis_acl_setuser_args("perch_run_x", "pw", "read")
    write = dpmod.redis_acl_setuser_args("perch_run_x", "pw", "write")
    assert read[:6] == ["redis-cli", "ACL", "SETUSER", "perch_run_x", "reset", "on"]
    assert ">pw" in read and "~*" in read
    # read: read commands but not @dangerous (no KEYS/FLUSHALL/CONFIG); no writes
    assert "+@read" in read and "-@dangerous" in read and "+@all" not in read
    assert "+@all" in write and "-@dangerous" in write        # write: data ops, no admin


def test_minio_provision_commands_scope_to_builtin_policy():
    read = dpmod.minio_provision_commands("root", "rootpw", "ak", "sk", "read")
    write = dpmod.minio_provision_commands("root", "rootpw", "ak", "sk", "write")
    assert read[0][:3] == ["mc", "alias", "set"]
    assert write[1][:4] == ["mc", "admin", "user", "add"]
    assert "readonly" in read[2] and "--user" in read[2] and "ak" in read[2]
    assert "readwrite" in write[2]


def test_redis_and_minio_connection_env():
    assert dpmod.redis_connection_env("p", "cache", "u", "pw")["REDIS_URL"] == \
        "redis://u:pw@perch-p-cache:6379"
    s = dpmod.minio_connection_env("p", "files", "ak", "sk", ["media"])
    assert s["S3_ACCESS_KEY"] == "ak" and s["S3_BUCKETS"] == "media"
    assert s["S3_ENDPOINT"] == "http://perch-p-files:9000"


def test_identity_cache_redeems_into_per_run_user():
    a = svc("worker", type="agent", bindings=["cache"]); a.identity = True
    m = Manifest("p", [Service(name="cache", type="cache"), a])
    fdp = FakeDataPlane()
    env = dict(Reconciler(FakeBackend(), m, state=_state(), dataplane=fdp)._ctx(a, mint=True).env)
    assert "perch_run_" in env["REDIS_URL"]
    assert fdp.provisioned[0].stype == "cache" and fdp.provisioned[0].access == "write"


def test_apply_reaps_expired_creds_in_steady_state():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    st = State(root)
    st.put("_dataplane", [{"stype": "cache", "service": "cache", "cid": "perch_run_old", "exp": 0}])
    cache = Service(name="cache", type="cache")
    # cache already running and up to date -> noop; no workload reconverges, yet
    # the apply-level sweep must still reap the expired per-run user.
    live = LiveService("cache", "running", cache.source_hash(""), cache.config_hash(), health="none")
    fdp = FakeDataPlane()
    Reconciler(FakeBackend([live]), Manifest("p", [cache]), state=st, dataplane=fdp).apply()
    assert ("cache", "cache", ["perch_run_old"]) in fdp.reaped


def test_storage_reap_after_service_removed_uses_state_creds():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    st = State(root)
    st.put("p/files/user", "rootuser")            # previously-provisioned root keys
    st.put("p/files/password", "rootpw")
    st.put("_dataplane", [{"stype": "storage", "service": "files", "cid": "perch_run_old", "exp": 0}])
    captured = {}

    class CapturingDP(FakeDataPlane):
        def reap(self, project, stype, service, cids, admin=None):
            captured["admin"] = admin
            super().reap(project, stype, service, cids, admin)

    # 'files' is gone from the manifest -> admin recovered from state for reaping
    rec = Reconciler(FakeBackend(), Manifest("p", []), state=st, dataplane=CapturingDP())
    rec._reap_dataplane(rec._ensure_dataplane(), 999)
    assert captured["admin"] == {"user": "rootuser", "password": "rootpw"}


def test_identity_storage_redeems_with_admin_and_buckets():
    a = svc("worker", type="agent", bindings=["files"]); a.identity = {"scopes": {"files": "read"}}
    m = Manifest("p", [Service(name="files", type="storage", buckets=["media"]), a])
    fdp = FakeDataPlane()
    env = dict(Reconciler(FakeBackend(), m, state=_state(), dataplane=fdp)._ctx(a, mint=True).env)
    assert "perch_run_" in env["S3_ACCESS_KEY"]
    g = fdp.provisioned[0]
    assert g.stype == "storage" and g.access == "read"          # scope narrowed to read
    assert g.admin and g.admin.get("user") and g.buckets == ["media"]   # admin + buckets resolved


# ---- C8: egress control / network segmentation (perch/egress.py) --------
from perch import egress as egmod  # noqa: E402


def test_egress_policy_normalizes_and_fails_closed():
    assert egmod.policy(None) == ("all", [])           # absent -> full egress (compat)
    assert egmod.policy("all") == ("all", [])
    assert egmod.policy("deny") == ("deny", [])
    assert egmod.policy({"allow": ["api.x.com", " b.com "]}) == ("allow", ["api.x.com", "b.com"])
    assert egmod.policy("nonsense") == ("deny", [])    # explicit-but-unknown -> fail closed


def test_egress_network_selection():
    assert egmod.network_for("p", None) == "perch-p"            # full egress -> main
    assert egmod.network_for("p", "deny") == "perch-p-internal"
    assert egmod.network_for("p", {"allow": ["x"]}) == "perch-p-internal"


def test_egress_proxy_config_default_deny_and_filter():
    cfg = egmod.tinyproxy_config()
    assert "FilterDefaultDeny Yes" in cfg and "FilterURLs Off" in cfg   # host-only match
    flt = egmod.tinyproxy_filter(["api.anthropic.com"])
    assert r"api\.anthropic\.com$" in flt              # anchored host pattern (subdomains ok)


def test_egress_allow_keeps_managed_hosts_reachable():
    # bound managed services must bypass the proxy (NO_PROXY), or HTTP datastores
    # behind the default-deny proxy would be unreachable.
    agent = svc("worker", type="agent", bindings=["files"])
    agent.egress = {"allow": ["api.x.com"]}
    m = Manifest("p", [Service(name="files", type="storage", buckets=["b"]), agent])
    env = dict(Reconciler(FakeBackend(), m, state=_state())._ctx(agent).env)
    assert "perch-p-files" in env["NO_PROXY"]


def test_egress_optin_is_backwards_compatible():
    base = svc("web", port=8080)
    assert base.egress_policy == ("all", [])
    same = svc("web", port=8080); same.egress = None
    assert same.config_hash() == base.config_hash()    # absence -> unchanged hash
    locked = svc("web", port=8080); locked.egress = "deny"
    assert locked.config_hash() != base.config_hash()  # enabling is a real change


def test_reconcile_egress_deny_uses_internal_network():
    agent = svc("worker", type="agent"); agent.egress = "deny"
    ctx = Reconciler(FakeBackend(), Manifest("p", [agent]), state=_state())._ctx(agent)
    assert ctx.network == "perch-p-internal"
    assert "HTTP_PROXY" not in dict(ctx.env)            # deny needs no proxy


def test_reconcile_egress_allow_sets_proxy_env():
    agent = svc("worker", type="agent"); agent.egress = {"allow": ["api.x.com"]}
    ctx = Reconciler(FakeBackend(), Manifest("p", [agent]), state=_state())._ctx(agent)
    assert ctx.network == "perch-p-internal"
    env = dict(ctx.env)
    assert env["HTTP_PROXY"] == "http://perch-p-egress-worker:8888"


def test_reconcile_managed_attaches_both_networks():
    m = Manifest("p", [pg("db")])
    ctx = Reconciler(FakeBackend(), m, state=_state())._ctx(m.services[0])
    assert ctx.network == "perch-p" and ctx.extra_networks == ["perch-p-internal"]


def test_apply_brings_up_egress_proxy_for_allow_workload():
    agent = svc("worker", type="agent"); agent.egress = {"allow": ["api.x.com"]}
    fb = FakeBackend()
    Reconciler(fb, Manifest("p", [agent]), state=_state()).apply()
    assert ("egress_proxy", "worker", ["api.x.com"]) in fb.calls


def test_apply_attaches_managed_services_to_internal_network():
    fb = FakeBackend()
    Reconciler(fb, Manifest("p", [pg("db")]), state=_state()).apply()
    assert ("attach_internal", "db") in fb.calls       # idempotent upgrade attach


# ---- C9: MCP & tool-call mediation (perch/mediation.py) -----------------
from perch import mediation as medmod  # noqa: E402


def test_tool_policy_default_deny():
    pol = medmod.ToolPolicy()                          # empty allowlist
    assert not pol.authorized("github.create_issue")
    assert pol.authorize("anything").reason == "no allow rule matched (default deny)"


def test_tool_policy_glob_patterns():
    pol = medmod.ToolPolicy(["github.*", "fs.read_*", "search.query"])
    assert pol.authorized("github.create_issue")       # server wildcard
    assert pol.authorized("fs.read_file") and not pol.authorized("fs.write_file")
    assert pol.authorized("search.query") and not pol.authorized("search.delete")
    assert not pol.authorized("payments.charge")       # default deny
    assert medmod.ToolPolicy(["*"]).authorized("anything")   # allow-all


def test_tool_policy_wildcard_does_not_cross_dot_boundary():
    # '*' must not span the server.tool boundary -> can't escalate into a new segment
    pol = medmod.ToolPolicy(["github.*", "fs.read_*"])
    assert not pol.authorized("github.create_issue.extra")   # extra segment
    assert not pol.authorized("fs.read_file.escalate")


def test_tool_policy_pattern_metachars_are_literal():
    # '[', ']', '?' in a pattern match literally, never as regex/glob classes
    pol = medmod.ToolPolicy(["svc.tool[1]"])
    assert pol.authorized("svc.tool[1]") and not pol.authorized("svc.tool1")


def test_tool_policy_rejects_invalid_tool():
    pol = medmod.ToolPolicy(["*"])
    assert not pol.authorized("")                      # empty -> deny even under '*'
    assert not pol.authorized(None)
    assert not pol.authorized("github.x\nevil")        # control chars -> deny


def test_mediation_audit_record_is_deterministic():
    pol = medmod.ToolPolicy(["github.*"])
    rec = medmod.audit_record("perch://p/agent/a", pol.authorize("github.x"), at=1000)
    assert rec == {"subject": "perch://p/agent/a", "tool": "github.x",
                   "allowed": True, "reason": "allowed by 'github.*'", "at": 1000}


def test_manifest_mcp_policy_and_hash():
    a = svc("worker", type="agent")
    assert not a.mcp_enabled
    base = a.config_hash()
    a.mcp = {"allow": ["github.*"]}
    assert a.mcp_enabled and a.mcp_policy().authorized("github.x")
    assert a.config_hash() != base                     # enabling mcp is a real change


def test_reconcile_mcp_injects_gateway_env_only_when_set():
    # With the gateway shipped (C9), an mcp-enabled agent is pointed at its gateway;
    # an agent with no mcp block is untouched (backwards compatible).
    plain = svc("plain", type="agent")
    assert "PERCH_MCP_GATEWAY" not in dict(
        Reconciler(FakeBackend(), Manifest("p", [plain]), state=_state())._ctx(plain).env)
    a = svc("worker", type="agent"); a.mcp = {"allow": ["github.*"]}
    env = dict(Reconciler(FakeBackend(), Manifest("p", [a]), state=_state())._ctx(a).env)
    assert env["PERCH_MCP_GATEWAY"] == "http://perch-p-mcp-worker:8900"


def test_reconcile_apply_starts_mcp_gateway_with_policy():
    a = svc("worker", type="agent")
    a.mcp = {"allow": {"tools": ["github.*"]}, "servers": {"github": {"url": "https://u"}}}
    fb = FakeBackend()
    Reconciler(fb, Manifest("p", [a]), state=_state()).apply()
    gw = [c for c in fb.calls if c[0] == "mcp_gateway"]
    assert gw and gw[0][1] == "worker"
    cfg = gw[0][3]
    assert cfg["policy"]["tools"] == ["github.*"] and cfg["servers"] == {"github": {"url": "https://u"}}
    assert cfg["spool"] == "/var/perch/spool/mcp.jsonl" and cfg["port"] == 8900
    assert cfg["quarantined"] is False                        # not quarantined on a clean run


def test_reconcile_no_mcp_is_backwards_compatible():
    # Absent mcp: no gateway, no env, and an identical config hash.
    a = svc("worker", type="agent")
    base = a.config_hash()
    fb = FakeBackend()
    rec = Reconciler(fb, Manifest("p", [a]), state=_state())
    rec.apply()
    assert not any(c[0] == "mcp_gateway" for c in fb.calls)
    assert "PERCH_MCP_GATEWAY" not in dict(rec._ctx(a).env)
    assert a.config_hash() == base


# ---- C9: full-coverage mediation policy (perch/mediation.py) -------------
def test_mediation_policy_per_capability_default_deny():
    p = medmod.MediationPolicy(tools=["github.*"], resources=["fs://**"], prompts=["gh.*"])
    assert p.authorized_tool("github.x") and not p.authorized_tool("paypal.charge")
    assert p.authorized_resource("fs://a/b/c.txt") and not p.authorized_resource("s3://x")
    assert p.authorized_prompt("gh.review") and not p.authorized_prompt("evil.x")
    empty = medmod.MediationPolicy()
    assert not empty.authorized_tool("anything") and not empty.authorized_resource("fs://a")


def test_mediation_policy_resource_glob_segment_vs_recursive():
    p = medmod.MediationPolicy(resources=["fs://docs/*"])
    assert p.authorized_resource("fs://docs/readme")
    assert not p.authorized_resource("fs://docs/sub/file")     # * doesn't cross '/'
    assert medmod.MediationPolicy(resources=["fs://docs/**"]).authorized_resource("fs://docs/sub/file")


def test_mediation_policy_sampling_completion_default_deny():
    assert not medmod.MediationPolicy().sampling
    assert medmod.MediationPolicy(sampling=True).sampling
    assert not medmod.MediationPolicy().completion


def test_mediation_policy_old_allow_list_is_tools():
    p = medmod.MediationPolicy.from_manifest({"allow": ["github.*"]})
    assert p.authorized_tool("github.x") and not p.authorized_resource("fs://a")
    assert medmod.MediationPolicy.from_config(p.to_config()).authorized_tool("github.y")


# ---- C9: MCP protocol mediation (perch/mcp.py) --------------------------
from perch import mcp as mcpmod  # noqa: E402


def test_mcp_mediate_methods():
    p = medmod.MediationPolicy(tools=["github.read"], resources=["fs://**"], prompts=["gh.*"])
    call = lambda m, params=None: mcpmod.mediate({"id": 1, "method": m, "params": params or {}}, p)
    assert call("tools/call", {"name": "github.read"}).allowed
    assert not call("tools/call", {"name": "github.delete"}).allowed
    assert call("resources/read", {"uri": "fs://x"}).allowed
    assert not call("resources/read", {"uri": "s3://x"}).allowed
    assert call("prompts/get", {"name": "gh.review"}).allowed
    assert call("tools/list").allowed and call("tools/list").filter == "tools"
    assert not call("sampling/createMessage").allowed          # default deny
    assert medmod.MediationPolicy(sampling=True).sampling
    assert call("initialize").allowed and call("ping").allowed
    assert not call("evil/method").allowed                     # unknown -> fail closed


def test_mcp_mediate_fails_closed_on_malformed():
    p = medmod.MediationPolicy(tools=["*"])
    assert not mcpmod.mediate("not-an-object", p).allowed
    assert not mcpmod.mediate({"id": 1}, p).allowed            # no method
    assert not mcpmod.mediate({"id": 1, "method": "tools/call", "params": {"name": "a\nb"}}, p).allowed


def test_mcp_jsonrpc_error_shape():
    err = mcpmod.jsonrpc_error(7, "denied")
    assert err == {"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "denied"}}


# ---- C9: the gateway core (perch/gateway.py) ----------------------------
from perch import gateway as gwmod  # noqa: E402


class _FakeUpstreams:
    def __init__(self, names, responder):
        self._names = list(names)
        self._responder = responder
        self.sent = []
    def names(self): return list(self._names)
    def send(self, server, message):
        self.sent.append((server, message))
        return self._responder(server, message)


def _gw(policy, upstreams, spool=None):
    return gwmod.Gateway(project="p", service="w", subject="perch://p/agent/w",
                         policy=policy, upstreams=upstreams, spool=spool, clock=lambda: 1000)


def test_gateway_forwards_allowed_and_rewrites_name():
    pol = medmod.MediationPolicy(tools=["github.create_issue"])
    up = _FakeUpstreams(["github"], lambda s, m: {"jsonrpc": "2.0", "id": m["id"],
                                                  "result": {"ok": m["params"]["name"]}})
    r = _gw(pol, up).handle_payload({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": "github.create_issue"}})
    assert r["result"]["ok"] == "create_issue"                 # routed + name stripped to bare
    assert up.sent[0][0] == "github"


def test_gateway_denies_without_forwarding():
    pol = medmod.MediationPolicy(tools=["github.read_*"])
    up = _FakeUpstreams(["github"], lambda s, m: {"never": True})
    r = _gw(pol, up).handle_payload({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                     "params": {"name": "github.delete_repo"}})
    assert r["error"]["code"] == -32001 and up.sent == []      # denied, never forwarded


def test_gateway_filters_list_to_allowlist():
    pol = medmod.MediationPolicy(tools=["github.create_issue"])
    up = _FakeUpstreams(["github"], lambda s, m: {"jsonrpc": "2.0", "id": m["id"],
        "result": {"tools": [{"name": "create_issue"}, {"name": "delete_repo"}]}})
    r = _gw(pol, up).handle_payload({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert r["result"]["tools"] == [{"name": "github.create_issue"}]   # delete_repo stripped


def test_gateway_spools_decisions(tmp_path=None):
    import tempfile as _tf, json as _json, os as _os
    d = _tf.mkdtemp(); spool = _os.path.join(d, "mcp.jsonl")
    pol = medmod.MediationPolicy(tools=["github.read"])
    up = _FakeUpstreams(["github"], lambda s, m: {"jsonrpc": "2.0", "id": m["id"], "result": {}})
    g = _gw(pol, up, spool=spool)
    g.handle_payload({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "github.read"}})
    g.handle_payload({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "github.write"}})
    recs = [_json.loads(l) for l in open(spool) if l.strip()]
    assert recs[0]["allowed"] and recs[0]["subject"] == "perch://p/agent/w"
    assert not recs[1]["allowed"] and recs[1]["method"] == "tools/call"


def test_reconcile_ingests_mcp_spool_and_quarantines():
    # Denied tool calls in the spool drive the C11 Detector -> Quarantine loop.
    from perch import audit as auditmod
    a = svc("worker", type="agent"); a.mcp = {"allow": ["github.read"]}
    st = _state()
    rec = Reconciler(FakeBackend(), Manifest("p", [a]), state=st)
    subject = __import__("perch.identity", fromlist=["subject_for"]).subject_for("p", "worker", "agent")
    spool = st.path.parent / "mcp-spool" / "worker"
    spool.mkdir(parents=True)
    import json as _json
    with open(spool / "mcp.jsonl", "w") as f:
        for i in range(12):
            f.write(_json.dumps({"subject": subject, "method": "tools/call",
                                 "tool": "github.delete", "allowed": False, "at": i}) + "\n")
    rec._ingest_mcp_spools()
    q = auditmod.Quarantine.from_dict(st.get("_quarantine", {}))
    assert subject in q                                        # excessive_tool_denials tripped
    assert not (spool / "mcp.jsonl").exists()                 # spool atomically consumed


# ---- C9 hardening (folded from adversarial review) ----------------------
def test_mediation_rejects_whitespace_names_no_silent_strip():
    # str.strip() removes NBSP/U+2000.. that the control-char check misses; rejecting
    # instead of normalizing keeps the matched name == the forwarded/audited name.
    pol = medmod.ToolPolicy(["fs.read"])
    assert not pol.authorized("fs.read\xa0") and not pol.authorized("fs.read ")
    assert not pol.authorized(" fs.read") and not pol.authorized("fs.read ")
    assert not medmod.MediationPolicy(resources=["fs://x"]).authorized_resource("fs://x\xa0")
    # mediate() carries the validated name as target (no divergence between auth & forward)
    deny = mcpmod.mediate({"id": 1, "method": "tools/call", "params": {"name": "fs.read\xa0"}},
                          medmod.MediationPolicy(tools=["fs.read"]))
    assert not deny.allowed
    ok = mcpmod.mediate({"id": 1, "method": "tools/call", "params": {"name": "github.read"}},
                        medmod.MediationPolicy(tools=["github.*"]))
    assert ok.allowed and ok.target == "github.read"


def test_gateway_batch_size_capped():
    pol = medmod.MediationPolicy(tools=["*"])
    up = _FakeUpstreams(["s"], lambda s, m: {"jsonrpc": "2.0", "id": m.get("id"), "result": {}})
    big = [{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(mcpmod.MAX_BATCH_ELEMENTS + 1)]
    r = _gw(pol, up).handle_payload(big)
    assert isinstance(r, list) and len(r) == 1 and "batch too large" in r[0]["error"]["message"]
    assert up.sent == []                                  # rejected before any forwarding


def test_gateway_quarantined_denies_everything():
    pol = medmod.MediationPolicy(tools=["github.*"])
    up = _FakeUpstreams(["github"], lambda s, m: {"jsonrpc": "2.0", "id": m.get("id"), "result": {}})
    g = gwmod.Gateway(project="p", service="w", subject="s", policy=pol, upstreams=up,
                      quarantined=True, clock=lambda: 1)
    r = g.handle_payload({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "github.x"}})
    assert r["error"]["message"] == "perch: subject quarantined" and up.sent == []
    # even an otherwise-passthrough initialize is denied for a quarantined subject
    assert g.handle_payload({"jsonrpc": "2.0", "id": 2, "method": "initialize"})["error"]["code"] == -32001


def test_gateway_parses_json_and_sse_http_bodies():
    import json as _json
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    # plain application/json
    assert gwmod._parse_http_body("application/json", _json.dumps(payload).encode())["result"] == {"ok": True}
    # SSE / Streamable HTTP: the JSON-RPC message rides in a data: field (real hosted MCP servers)
    sse = f"event: message\ndata: {_json.dumps(payload)}\n\n".encode()
    assert gwmod._parse_http_body("text/event-stream", sse)["result"] == {"ok": True}
    # malformed body fails closed (never silently returns nothing)
    try:
        gwmod._parse_http_body("application/json", b"not json")
        assert False, "expected GatewayError"
    except gwmod.GatewayError:
        pass


# ---- C9 agent wiring + worked example -----------------------------------
def test_gateway_client_config_shape():
    srv = medmod.gateway_client_config("proj", "worker")["mcpServers"]["perch-gateway"]
    assert srv["type"] == "http" and srv["url"] == "http://perch-proj-mcp-worker:8900/"


def _example_path():
    import os as _os
    return _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                         "examples", "secure-agent", "perch.yaml")


def test_example_secure_agent_manifest_parses():
    a = Manifest.load(_example_path()).by_name()["assistant"]
    assert a.mcp_enabled and a.identity_enabled
    assert a.mcp_servers == {"github": "https://mcp.example.com/github"}
    assert a.mcp_policy().authorized_tool("github.search_repos")
    assert not a.mcp_policy().authorized_tool("github.delete_repo")
    assert a.identity_access("db") == "read"


def test_cli_mcp_config_command():
    import io, contextlib, json
    from perch.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["-f", _example_path(), "mcp-config", "assistant"])
    out = json.loads(buf.getvalue())
    srv = out["mcpServers"]["perch-gateway"]
    assert rc == 0 and srv["url"].endswith(":8900/")
    assert srv["headers"]["Authorization"].startswith("Bearer ")   # C1 token included by default


# ---- C9/C1: per-agent gateway token auth --------------------------------
def test_gateway_token_auth_constant_time_and_optional():
    assert gwmod._token_ok(None, None)                     # no expected token -> auth disabled
    assert gwmod._token_ok("secret", "secret")
    assert not gwmod._token_ok("secret", "wrong")
    assert not gwmod._token_ok("secret", None)             # required but absent -> deny
    assert not gwmod._token_ok("secret", "sécret")    # non-ASCII -> clean deny, never a crash
    assert not gwmod._token_ok("", "anything")             # empty expected is NOT "disabled" -> deny
    assert gwmod._bearer({"Authorization": "Bearer abc"}) == "abc"
    assert gwmod._bearer({"X-Perch-Token": "xyz"}) == "xyz"
    assert gwmod._bearer({}) is None


def test_mcp_auth_default_on_and_optout():
    a = svc("worker", type="agent")
    a.mcp = {"allow": ["github.*"]}
    assert a.mcp_auth                                       # on by default when mcp is set
    a.mcp = {"allow": ["github.*"], "auth": False}
    assert not a.mcp_auth


def test_reconcile_injects_gateway_token_and_bakes_it_in_config():
    a = svc("worker", type="agent"); a.mcp = {"allow": ["github.*"]}
    st = _state()
    fb = FakeBackend()
    rec = Reconciler(fb, Manifest("p", [a]), state=st)
    rec.apply()
    cfg = [c for c in fb.calls if c[0] == "mcp_gateway"][0][3]
    token = cfg["auth_token"]
    assert token                                           # gateway requires a token by default
    env = dict(rec._ctx(a, mint=True).env)
    assert env["PERCH_MCP_TOKEN"] == token                 # agent gets the matching token
    # opt-out drops the token on both sides
    a.mcp = {"allow": ["github.*"], "auth": False}
    assert rec._mcp_token(a) is None
    assert "PERCH_MCP_TOKEN" not in dict(rec._ctx(a, mint=True).env)


# ---- C10: agent memory integrity & provenance (perch/memory.py) ---------
from perch import memory as memmod  # noqa: E402


def test_memory_append_chain_and_verify():
    log = memmod.MemoryLog()
    r0 = log.append({"note": "hello"})
    r1 = log.append({"note": "world"})
    assert r0.prev_hash == memmod.GENESIS and r1.prev_hash == r0.hash   # provenance links
    assert r0.seq == 0 and r1.seq == 1
    assert log.verify() and log.head() == r1.hash


def test_memory_detects_tampered_record():
    log = memmod.MemoryLog()
    log.append({"x": 1}); log.append({"x": 2})
    log._records[0].data["x"] = 99                     # poison an earlier record in place
    assert not log.verify()                            # hash no longer matches contents


def test_memory_detects_reorder_and_truncation():
    key = b"memory-anchor-key-0123456789abcd"
    log = memmod.MemoryLog()
    for i in range(4):
        log.append({"i": i})
    anchor = log.anchor(key)
    assert log.verify_against(key, anchor)
    # reorder -> chain breaks
    reordered = memmod.MemoryLog(list(reversed(log.records())))
    assert not reordered.verify()
    # truncation: the shorter chain is internally consistent, but the anchor
    # (which binds the length + head) no longer matches -> detected.
    truncated = memmod.MemoryLog(log.records()[:3])
    assert truncated.verify() and not truncated.verify_against(key, anchor)


def test_memory_anchor_detects_whole_chain_forgery():
    key = b"memory-anchor-key-0123456789abcd"
    log = memmod.MemoryLog()
    log.append({"real": 1}); log.append({"real": 2})
    anchor = log.anchor(key)
    # attacker rebuilds a *consistent* alternate chain (verify() passes) but can't
    # reproduce the anchor without the key.
    forged = memmod.MemoryLog()
    forged.append({"fake": 1}); forged.append({"fake": 2})
    assert forged.verify() and not forged.verify_against(key, anchor)


def test_memory_anchor_rejects_short_key():
    log = memmod.MemoryLog(); log.append({"x": 1})
    try:
        log.anchor(b"short"); assert False, "short key must be rejected"
    except ValueError:
        pass


def test_memory_rejects_noncanonical_data():
    log = memmod.MemoryLog()
    for bad in ({1: "x"}, {"ok": float("nan")}, [{"nested": {2: "y"}}]):
        try:
            log.append(bad); assert False, f"non-canonical {bad!r} must be rejected"
        except ValueError:
            pass


def test_memory_serialization_roundtrip_preserves_integrity():
    key = b"memory-anchor-key-0123456789abcd"
    log = memmod.MemoryLog()
    for i in range(3):
        log.append({"i": i})
    anchor = log.anchor(key)
    back = memmod.MemoryLog.from_dict(log.to_dict())
    assert back.verify() and back.verify_against(key, anchor)


# ---- C11: detection -- audit log, anomaly detector, quarantine ----------
from perch import audit as auditmod  # noqa: E402


def test_audit_log_is_tamper_evident():
    key = b"audit-anchor-key-0123456789abcd!"
    log = auditmod.AuditLog()
    log.record(auditmod.ISSUE, "perch://p/agent/a", "db", at=1)
    log.record(auditmod.DENY, "perch://p/agent/b", "cache", at=2)
    anchor = log.anchor(key)
    assert log.verify_against(key, anchor) and len(log.events()) == 2
    log._log._records[0].data["subject"] = "perch://p/agent/evil"   # tamper
    assert not log.verify_against(key, anchor)


def test_detector_flags_excessive_failures():
    events = ([{"subject": "s1", "kind": auditmod.DENY}] * 5 +
              [{"subject": "s2", "kind": auditmod.ATTEST_FAIL}] * 3 +
              [{"subject": "s3", "kind": auditmod.ISSUE}] * 10)
    anomalies = auditmod.Detector().scan(events)
    flagged = {a.subject for a in anomalies}
    assert "s1" in flagged and "s2" in flagged    # over thresholds
    assert "s3" not in flagged                      # successful issues aren't anomalies


def test_quarantine_roundtrip():
    q = auditmod.Quarantine()
    q.add("perch://p/agent/a")
    assert "perch://p/agent/a" in q
    assert auditmod.Quarantine.from_dict(q.to_dict()).subjects() == ["perch://p/agent/a"]


def test_broker_audits_and_refuses_quarantined_subject():
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal("agent", ("db",))))
    sub = issued.identity.subject
    audit = auditmod.AuditLog()
    quar = auditmod.Quarantine()
    brk = brkmod.Broker(store, audit=audit, quarantine=quar, clock=lambda: 100)
    # a normal issue is audited
    c, p = _proof(issued)
    brk.issue(sub, "db", challenge=c, proof=p)
    assert any(e["kind"] == auditmod.ISSUE and e["subject"] == sub for e in audit.events())
    # quarantine the subject -> the broker refuses and audits the denial
    quar.add(sub)
    c, p = _proof(issued)
    try:
        brk.issue(sub, "db", challenge=c, proof=p); assert False, "quarantined must deny"
    except brkmod.BrokerDenied:
        pass
    assert any(e["kind"] == auditmod.DENY and "quarantined" in e["detail"] for e in audit.events())


def test_reconcile_persists_tamper_evident_audit():
    import tempfile
    from perch.state import State
    root = tempfile.mkdtemp()
    m, agent = _agent_with_db()
    Reconciler(FakeBackend(), m, state=State(root), dataplane=FakeDataPlane())._ctx(agent, mint=True)
    st = State(root)
    assert st.get("_audit") and st.get("_audit/anchor")          # audit + anchor persisted
    # a fresh reconciler verifies the audit against its anchor and loads fine
    Reconciler(FakeBackend(), m, state=State(root), dataplane=FakeDataPlane())._ensure_broker()
    # tamper the persisted audit -> the next load must fail closed
    bad = st.get("_audit"); bad["records"][0]["data"]["subject"] = "evil"; st.put("_audit", bad)
    try:
        Reconciler(FakeBackend(), m, state=State(root), dataplane=FakeDataPlane())._ensure_broker()
        assert False, "tampered audit must fail closed"
    except ValueError as e:
        assert "tamper" in str(e)


def test_detection_loop_quarantines_then_broker_denies():
    # end-to-end: repeated denials -> detector flags -> quarantine -> broker denies
    store = idmod.IdentityStore()
    issued = store.register(idmod.issue(_principal("agent", ("db",))))
    sub = issued.identity.subject
    audit = auditmod.AuditLog(); quar = auditmod.Quarantine()
    brk = brkmod.Broker(store, audit=audit, quarantine=quar, clock=lambda: 1)
    for _ in range(5):                              # 5 out-of-scope (denied) attempts
        c, p = _proof(issued)
        try:
            brk.issue(sub, "cache", challenge=c, proof=p)   # not scoped for cache
        except brkmod.BrokerDenied:
            pass
    for a in auditmod.Detector().scan(audit.events()):
        quar.add(a.subject)
    assert sub in quar                              # flagged + quarantined
    c, p = _proof(issued)
    try:
        brk.issue(sub, "db", challenge=c, proof=p); assert False   # even a valid request denied
    except brkmod.BrokerDenied:
        pass


# ---- C12: supply-chain integrity (perch/supplychain.py) -----------------
from perch import supplychain as scmod  # noqa: E402

_PIN = "sha256:" + "a" * 64                               # a well-formed digest
_PIN2 = "sha256:" + "b" * 64


def test_parse_image_components():
    r = scmod.parse_image(f"ghcr.io/acme/app:1.2@{_PIN}")
    assert r.registry == "ghcr.io" and r.repo == "acme/app" and r.tag == "1.2"
    assert r.digest == _PIN and r.pinned
    d = scmod.parse_image("redis:7-alpine")               # default registry, no digest
    assert d.registry == "docker.io" and d.repo == "redis" and d.tag == "7-alpine"
    assert not d.pinned
    assert not scmod.parse_image("a@sha256:abc").pinned   # short digest is NOT a pin


def test_digest_policy_requires_pin_and_registry():
    pol = scmod.DigestPolicy(require_pinned=True, allow_registries=["ghcr.io"])
    assert pol.check(f"ghcr.io/acme/app@{_PIN}")[0]               # pinned + allowed
    assert not pol.check("ghcr.io/acme/app:latest")[0]           # unpinned -> deny
    assert not pol.check("ghcr.io/acme/app@sha256:abc")[0]       # malformed digest -> deny
    assert not pol.check(f"docker.io/acme/app@{_PIN}")[0]        # registry not allowed
    assert pol.check(None)[0]                                     # built locally -> ok


def test_digest_policy_actual_digest_fail_closed():
    pol = scmod.DigestPolicy(require_pinned=True)
    assert pol.check_actual(f"ghcr.io/a@{_PIN}", _PIN)[0]
    assert not pol.check_actual(f"ghcr.io/a@{_PIN}", _PIN2)[0]    # mismatch
    assert not pol.check_actual(f"ghcr.io/a@{_PIN}", "")[0]       # unresolved -> fail closed


def test_supply_chain_optin_is_backwards_compatible():
    base = svc("web", port=8080)
    assert base.supply_chain_policy() is None
    same = svc("web", port=8080); same.verify = None
    assert same.config_hash() == base.config_hash()
    pinned = svc("web", port=8080); pinned.verify = {"pin": True}
    assert pinned.config_hash() != base.config_hash()


def test_apply_blocks_unpinned_image_under_policy():
    s = Service(name="app", type="webapp", image="acme/app:latest", verify={"pin": True})
    rec = Reconciler(FakeBackend(), Manifest("p", [s]), state=_state())
    try:
        rec.apply(); assert False, "unpinned image must be blocked"
    except ValueError as e:
        assert "not pinned" in str(e)
    # a pinned image is allowed to run
    ok = Service(name="app", type="webapp", image=f"acme/app@{_PIN}", verify={"pin": True})
    fb = FakeBackend()
    Reconciler(fb, Manifest("p", [ok]), state=_state()).apply()
    assert ("converge", "app") in fb.calls


def test_apply_blocks_managed_unpinned_image_under_policy():
    # C12 must check the CATALOG image for managed services, not svc.image (None).
    db = pg("db"); db.verify = {"pin": True}              # pgvector:pgN is not pinned
    rec = Reconciler(FakeBackend(), Manifest("p", [db]), state=_state())
    try:
        rec.apply(); assert False, "unpinned catalog image must be blocked"
    except ValueError as e:
        assert "not pinned" in str(e)


# ---- C: daemon-free manifest validation (`perch validate`) -----------------
def test_validate_accepts_clean_manifest():
    assert Manifest("p", [svc("web", port=8080)]).validate() == []


def test_validate_flags_duplicate_names_and_unknown_type():
    m = Manifest("p", [svc("web", port=8080), Service(name="web", type="mystery")])
    probs = m.validate()
    assert any("duplicate service name" in p for p in probs)
    assert any("unknown type" in p for p in probs)


def test_validate_workload_needs_build_or_image():
    bare = Service(name="agent", type="agent")            # no build, no image
    assert any("needs `build:` or `image:`" in p for p in Manifest("p", [bare]).validate())
    withimg = Service(name="agent", type="agent", image="acme/a:1")
    assert not any("needs `build:`" in p for p in Manifest("p", [withimg]).validate())


def test_validate_binding_must_exist_and_be_managed():
    web = svc("web", port=8080)                            # a webapp, not a datastore
    worker = Service(name="worker", type="agent", build=Build("./x"),
                     bindings=["web", "ghost"])
    probs = Manifest("p", [web, worker]).validate()
    assert any("binding 'ghost' references no service" in p for p in probs)
    assert any("binding 'web' is not a managed" in p for p in probs)
    # binding a real datastore is clean
    ok = Service(name="worker", type="agent", build=Build("./x"), bindings=["db"])
    assert Manifest("p", [pg("db"), ok]).validate() == []


def test_validate_rest_api_database_reference():
    api = Service(name="api", type="rest-api", database="db")   # db missing
    assert any("references no service" in p for p in Manifest("p", [api]).validate())
    api2 = Service(name="api", type="rest-api", database="db")
    assert Manifest("p", [pg("db"), api2]).validate() == []


def test_validate_webapp_route_needs_port():
    s = svc("web", route=Route(host="web.localhost"))     # route but no port
    assert any("route.host set but no `port:`" in p for p in Manifest("p", [s]).validate())


def test_validate_flags_invalid_mcp_policy():
    s = Service(name="a", type="agent", build=Build("./x"), mcp=["not", "a", "dict"])
    assert any("invalid mcp policy" in p for p in Manifest("p", [s]).validate())


# ---- perch share: LAN sharing helpers (perch/share.py, proxy, doctor) -------
from perch import share as sharemod  # noqa: E402


def test_share_allocate_port_stable_and_skips_used():
    assert sharemod.allocate_port({}) == sharemod.SHARE_BASE
    assert sharemod.allocate_port({"web": 8100, "api": 8101}) == 8102
    try:
        sharemod.allocate_port({f"s{i}": p for i, p in
                                enumerate(range(sharemod.SHARE_BASE, sharemod.SHARE_MAX + 1))})
        assert False, "exhausted range must fail loud"
    except ValueError:
        pass


def test_share_caddyfile_port_block_and_backcompat():
    from perch import proxy as proxymod
    m = Manifest("p", [svc("web", port=8080, route=Route(host="web.localhost"))])
    base = proxymod.caddyfile(m)
    assert proxymod.caddyfile(m, None) == base          # no shares -> byte-identical
    shared = proxymod.caddyfile(m, {"web": 8100})
    assert "http://:8100 {" in shared and "reverse_proxy perch-p-web:8080" in shared
    # a share for a missing/portless service is skipped, not an error
    assert "8101" not in proxymod.caddyfile(m, {"ghost": 8101})


def test_share_classify_matrix_distinguishes_failure_modes():
    ok, _ = sharemod.classify(True, True, False)
    assert ok == "REACHABLE"
    wsl_status, wsl_msg = sharemod.classify(False, True, True)
    fw_status, fw_msg = sharemod.classify(False, True, False)
    other_status, _ = sharemod.classify(False, False, False)
    assert "WSL" in wsl_status and "portproxy" in wsl_msg      # different fixes,
    assert "Firewall" in fw_status and "--fix" in fw_msg       # different messages
    assert wsl_msg != fw_msg and other_status.startswith("BLOCKED")


def test_share_firewall_rule_scoped_to_private_domain_never_public():
    spec = sharemod.firewall_rule_spec(8100)
    assert "-LocalPort 8100" in spec and "-Direction Inbound" in spec
    assert "-Profile Domain,Private" in spec and "Public" not in spec.replace(
        "Domain,Private", "")


def test_share_policy_merge_disabled_detection():
    assert sharemod.policy_merge_disabled(read=lambda p, n: 0)          # GPO disables
    assert not sharemod.policy_merge_disabled(read=lambda p, n: 1)      # explicit on
    assert not sharemod.policy_merge_disabled(read=lambda p, n: None)   # no policy
    # only Domain/Private profiles considered
    calls = []
    sharemod.policy_merge_disabled(read=lambda p, n: calls.append(p))
    assert set(calls) == {"DomainProfile", "StandardProfile"}


def test_share_cli_validation_fails_before_docker():
    import tempfile as _tf
    from perch.cli import main
    d = _tf.mkdtemp()
    path = os.path.join(d, "perch.yaml")
    with open(path, "w") as f:
        f.write("project: p\nservices:\n  - name: worker\n    type: agent\n"
                "    build: { context: ./x }\n")
    for argv, needle in ((["-f", path, "share", "nosuch"], "no service named"),
                         (["-f", path, "share", "worker"], "has no `port:`")):
        try:
            main(argv); assert False, f"{argv} must exit"
        except SystemExit as e:
            assert needle in str(e.code)


# ---- sharing sprint 2: tailscale, https shares, mdns -------------------------
def test_share_normalize_shares_accepts_both_state_shapes():
    out = sharemod.normalize_shares(
        {"a": 8100, "b": {"port": 8101, "https": True}, "c": {"port": 8102},
         "bad": "x", "worse": {"port": "y"}})
    assert out == {"a": {"port": 8100, "https": False},
                   "b": {"port": 8101, "https": True},
                   "c": {"port": 8102, "https": False}}
    assert sharemod.allocate_port(out) == 8103          # dict entries counted too


def test_share_tailscale_dns_parse_and_hint():
    js = '{"Self": {"DNSName": "mybox.tail1234.ts.net."}}'
    assert sharemod._dns_from_status(js) == "mybox.tail1234.ts.net"
    assert sharemod._dns_from_status('{"Self": {}}') is None
    assert sharemod._dns_from_status("not json") is None
    assert sharemod._dns_from_status("{}") is None
    assert "tailscale" in sharemod.tailscale_hint(True)
    assert sharemod.tailscale_hint(False) is None


def test_share_caddyfile_https_block_uses_internal_ca():
    from perch import proxy as proxymod
    m = Manifest("p", [svc("web", port=8080)])
    out = proxymod.caddyfile(m, {"web": {"port": 8100, "https": True}})
    assert "https://:8100 {" in out and "tls internal" in out
    assert "reverse_proxy perch-p-web:8080" in out
    plain = proxymod.caddyfile(m, {"web": {"port": 8100, "https": False}})
    assert "http://:8100 {" in plain and "tls internal" not in plain


def test_share_cli_rejects_https_plus_tailscale():
    from perch.cli import main
    try:
        main(["share", "web", "--https", "--tailscale"])
        assert False, "combo must exit"
    except SystemExit as e:
        assert "pick one" in str(e.code)


def _mdns_query(name, qtype=1, qclass=1, flags=0):
    import struct as _s
    from perch import mdns
    return (_s.pack("!6H", 0, flags, 1, 0, 0, 0)
            + mdns.encode_name(name) + _s.pack("!2H", qtype, qclass))


def test_mdns_name_roundtrip():
    from perch import mdns
    raw = mdns.encode_name("web.local")
    assert mdns.decode_name(raw, 0) == ("web.local", len(raw))
    try:
        mdns.encode_name("bad..label"); assert False
    except ValueError:
        pass


def test_mdns_answers_matching_a_query():
    import socket as _sock
    from perch import mdns
    names = {"web.local": "192.168.1.42"}
    for qtype in (1, 255):                              # A and ANY
        resp = mdns.answer(_mdns_query("web.local", qtype=qtype), names)
        assert resp is not None
        assert resp[2:4] == b"\x84\x00"                 # authoritative response
        assert _sock.inet_aton("192.168.1.42") in resp
    # case-insensitive; unicast-response bit in qclass still matches
    assert mdns.answer(_mdns_query("WEB.LOCAL"), names) is not None
    assert mdns.answer(_mdns_query("web.local", qclass=0x8001), names) is not None


def test_mdns_fails_closed():
    from perch import mdns
    names = {"web.local": "192.168.1.42"}
    assert mdns.answer(_mdns_query("other.local"), names) is None      # not ours
    assert mdns.answer(_mdns_query("web.local", qtype=28), names) is None  # AAAA
    assert mdns.answer(_mdns_query("web.local", flags=0x8400), names) is None  # a response
    assert mdns.answer(b"\x00\x01", names) is None                     # truncated
    assert mdns.answer(_mdns_query("web.local")[:-2], names) is None   # cut question
    assert mdns.answer(b"", names) is None


def test_doctor_runtime_flavor_matrix():
    from perch.cli import _runtime_flavor
    assert "Desktop" in _runtime_flavor("Docker Desktop 4.30", "5.15.146")
    assert "paid license" in _runtime_flavor("Docker Desktop 4.30", "x")
    assert _runtime_flavor("Podman Engine", "x").startswith("Podman")
    wsl = _runtime_flavor("Docker Engine - Community", "5.15.153.1-microsoft-standard-WSL2")
    assert "WSL2" in wsl and "license-free" in wsl
    plain = _runtime_flavor("Docker Engine - Community", "6.8.0-generic")
    assert plain == "Docker Engine (license-free)"
    assert "license-free" in _runtime_flavor("", "")            # unknown fails safe


# ---- integration: the flagship example composes C1 + C8 + C9 + C11 ----------
def test_secure_agent_example_composes_all_controls():
    """The flagship example manifest, as written on disk, wires per-agent identity +
    gateway token (C1), default-deny egress (C8), and MCP mediation (C9) into ONE
    agent's runtime context -- and a burst of denied tool calls drives the detector
    to quarantine it (C11). Proves the controls compose, not just that each works
    alone. The gateway *container* is separately proven on real Docker by
    tests/docker_gateway_check.py and tests/e2e_gateway.py."""
    import json as _json
    from perch import audit as _audit
    from perch.identity import subject_for
    m = Manifest.load(_example_path())
    assistant = m.by_name()["assistant"]

    # C8: egress is default-deny with exactly the one declared host.
    mode, hosts = assistant.egress_policy
    assert mode == "allow" and hosts == ["api.anthropic.com"]

    # C1 + C9: the agent's runtime env points at its mediating gateway, carries a
    # per-agent bearer token, and declares its identity subject -- no static secret.
    rec = Reconciler(FakeBackend(), m, state=_state())
    env = dict(rec._ctx(assistant).env)            # mint=False: deterministic, no provisioning
    subject = subject_for(m.project, "assistant", "agent")
    assert env["PERCH_MCP_GATEWAY"].endswith(":8900")
    assert env["PERCH_MCP_TOKEN"]                  # C1 per-agent gateway bearer present
    assert env["PERCH_IDENTITY_SUBJECT"] == subject
    # the gateway is the agent's only outbound path, so it bypasses the egress proxy
    gw_host = medmod.gateway_name(m.project, "assistant")
    assert any(gw_host in str(v) for v in env.values())

    # C11: repeated denied tool calls (spooled by the gateway) quarantine the subject.
    spool = rec.state.path.parent / "mcp-spool" / "assistant"
    spool.mkdir(parents=True)
    with open(spool / "mcp.jsonl", "w") as f:
        for i in range(12):
            f.write(_json.dumps({"subject": subject, "method": "tools/call",
                                 "tool": "github.delete_repo", "allowed": False, "at": i}) + "\n")
    rec._ingest_mcp_spools()
    q = _audit.Quarantine.from_dict(rec.state.get("_quarantine", {}))
    assert subject in q


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(tests)} passed")
