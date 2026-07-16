"""
Composed apply() e2e: does ONE `Reconciler.apply()` on a real Docker host bring up
an agent with identity + egress + MCP mediation wired together, the way the
secure-agent example promises?

Every piece is already proven in isolation (offline suite; gateway container in
docker_gateway_check.py). This closes the remaining gap: the composition through
the real apply() path on a real daemon. Needs Docker, so it is NOT in the offline
suite; CI runs it in the integration job. Locally:

    python tests/compose_e2e.py

Asserts, after a single apply():
  * the agent, its egress proxy sidecar, and its MCP gateway sidecar are running,
  * the agent sits on the INTERNAL network only (egress allow => no direct route),
  * inside the agent: PERCH_IDENTITY_SUBJECT / PERCH_MCP_GATEWAY / PERCH_MCP_TOKEN
    are present, the gateway answers /healthz over the internal net, and a
    non-allow-listed tool call comes back as a JSON-RPC deny (-32001),
  * the gateway's decision landed in the host-side spool.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROJECT = "perchcompose"
SERVICE = "worker"

_MANIFEST = """\
project: perchcompose
services:
  - name: worker
    type: agent
    image: python:3.12-slim
    command: ["python", "-c", "import time; time.sleep(3600)"]
    identity: true
    egress: { allow: [api.example.com] }
    mcp:
      allow: { tools: ["echo.say"] }
"""

# Runs INSIDE the agent container: the composed proof from the workload's own
# point of view, using only its injected environment.
_PROBE = r'''
import json, os, sys, time, urllib.request
subject = os.environ.get("PERCH_IDENTITY_SUBJECT", "")
gw = os.environ.get("PERCH_MCP_GATEWAY", "")
tok = os.environ.get("PERCH_MCP_TOKEN", "")
print("PASS identity subject injected" if subject.startswith("perch://") else "FAIL subject: %r" % subject)
print("PASS gateway env injected" if gw.startswith("http://") else "FAIL gateway env: %r" % gw)
print("PASS gateway token injected" if tok else "FAIL no token")
base = gw.rstrip("/") + "/"
for _ in range(30):
    try:
        if urllib.request.urlopen(base + "healthz", timeout=3).status == 200:
            print("PASS gateway healthz over internal net"); break
    except Exception:
        time.sleep(1)
else:
    print("FAIL gateway unreachable"); sys.exit(1)
req = urllib.request.Request(base, data=json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "evil.delete_everything"}}).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok})
out = json.loads(urllib.request.urlopen(req, timeout=10).read())
if out.get("error", {}).get("code") == -32001:
    print("PASS denied tool -> JSON-RPC -32001")
else:
    print("FAIL denied-tool response: %r" % out); sys.exit(1)
'''


def _docker(*args, check=True, capture=True):
    return subprocess.run(["docker", *args], text=True,
                          capture_output=capture, check=check)


def _running(name: str) -> str:
    return _docker("inspect", "-f", "{{.State.Running}}", name,
                   check=False).stdout.strip()


def run() -> int:
    if shutil.which("docker") is None:
        print("SKIP: docker not on PATH")
        return 0
    try:
        _docker("info")
    except Exception as e:
        print(f"SKIP: docker daemon not available ({e})")
        return 0

    from perch import egress, mediation
    from perch.docker_backend import DockerBackend
    from perch.manifest import Manifest
    from perch.reconcile import Reconciler
    from perch.state import State

    work = tempfile.mkdtemp(prefix="perch-compose-")
    mpath = os.path.join(work, "perch.yaml")
    with open(mpath, "w") as f:
        f.write(_MANIFEST)
    m = Manifest.load(mpath)
    st = State(os.path.join(work, ".perch"))

    agent = f"perch-{PROJECT}-{SERVICE}"
    proxy = egress.proxy_name(PROJECT, SERVICE)
    gateway = mediation.gateway_name(PROJECT, SERVICE)
    fails: list[str] = []

    def check(name, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f"  -- {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    print("applying the composed manifest via Reconciler.apply() ...")
    try:
        Reconciler(DockerBackend(), m, state=st).apply()
        time.sleep(2)

        check("agent container running", _running(agent) == "true")
        check("egress proxy sidecar running", _running(proxy) == "true")
        check("mcp gateway sidecar running", _running(gateway) == "true")

        nets = _docker("inspect", "-f",
                       "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
                       agent, check=False).stdout.split()
        check("agent on internal network only (C8)",
              nets == [egress.internal_network(PROJECT)], f"got {nets}")

        probe = _docker("exec", agent, "python", "-c", _PROBE, check=False)
        sys.stdout.write(probe.stdout)
        sys.stderr.write(probe.stderr)
        check("in-container composed probe", probe.returncode == 0
              and "FAIL" not in probe.stdout)

        # the deny above must land in the host-side spool the reconciler ingests
        spool = os.path.join(work, ".perch", "mcp-spool", SERVICE, "mcp.jsonl")
        time.sleep(1)
        recs = []
        if os.path.exists(spool):
            with open(spool) as f:
                recs = [json.loads(line) for line in f if line.strip()]
        check("denied decision spooled for audit ingest",
              any(r.get("tool") == "evil.delete_everything" and not r.get("allowed")
                  for r in recs), f"spool records: {recs}")
    finally:
        for c in (agent, proxy, gateway):
            _docker("rm", "-f", c, check=False)
        _docker("network", "rm", egress.main_network(PROJECT),
                egress.internal_network(PROJECT), check=False)

    print(f"\n==== compose e2e: {'PASS' if not fails else 'FAIL: ' + ', '.join(fails)} ====")
    return 0 if not fails else 2


if __name__ == "__main__":
    raise SystemExit(run())
