"""
Docker integration check for C9: does DockerBackend.ensure_mcp_gateway actually launch
a working, reachable, mediating gateway CONTAINER?

This is the one link the socket-level test (tests/e2e_gateway.py) can't cover: the
container launch wiring -- mounting the perch package read-only, running
`python -m perch.gateway` on a minimal image, binding the port, attaching to the
project networks. It needs a Docker daemon, so it is NOT in the offline suite; CI runs
it on a Docker-enabled runner. Run locally with:

    python tests/docker_gateway_check.py

It launches the gateway via the real backend, then probes it from a SIBLING container on
the internal network (so this also proves network reachability + the per-agent token
auth), asserting: /healthz 200, an unauthenticated POST -> 401, and an authenticated
call to a non-allow-listed tool -> a JSON-RPC deny. No upstream server is needed (the
deny + healthz paths don't reach one); forwarding is already proven by e2e_gateway.py.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROJECT = "perchci"
SERVICE = "agent"
TOKEN = "ci-per-agent-token"

_PROBE = r'''
import json, sys, time, urllib.request, urllib.error
base, token = sys.argv[1], sys.argv[2]
def post(body, tok):
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(base, data=json.dumps(body).encode(), headers=h)
    return urllib.request.urlopen(req, timeout=10)
# wait for readiness
for _ in range(30):
    try:
        if urllib.request.urlopen(base + "healthz", timeout=3).status == 200:
            break
    except Exception:
        time.sleep(1)
else:
    print("FAIL healthz unreachable"); sys.exit(1)
fails = []
print("PASS healthz 200")
try:
    post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, None)
    fails.append("unauthenticated request was NOT rejected")
except urllib.error.HTTPError as he:
    print("PASS unauth -> %d" % he.code)
    if he.code != 401:
        fails.append("unauth code %d != 401" % he.code)
try:
    r = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo.delete"}}, token)
    out = json.loads(r.read())
    assert "error" in out and out["error"]["code"] == -32001, out
    print("PASS denied tool -> JSON-RPC error")
except Exception as e:
    fails.append("denied-tool path: %r" % (e,))
if fails:
    print("FAILURES:", fails); sys.exit(1)
print("ALL PASS")
'''


def _docker(*args, check=True):
    return subprocess.run(["docker", *args], text=True, capture_output=True, check=check)


def run() -> int:
    if shutil.which("docker") is None:
        print("SKIP: docker not on PATH (this check requires a Docker daemon)")
        return 0
    try:
        _docker("info", check=True)
    except Exception as e:
        print(f"SKIP: docker daemon not available ({e})")
        return 0

    from perch import mediation
    from perch.docker_backend import DockerBackend

    work = tempfile.mkdtemp(prefix="perch-docker-ci-")
    spool_dir = os.path.join(work, "mcp-spool", SERVICE)
    cname = mediation.gateway_name(PROJECT, SERVICE)
    from perch import egress
    internal_net = egress.internal_network(PROJECT)

    b = DockerBackend()
    config = {
        "project": PROJECT, "service": SERVICE, "subject": f"perch://{PROJECT}/agent/{SERVICE}",
        "port": mediation.GATEWAY_PORT,
        "policy": {"tools": ["echo.say"], "resources": [], "prompts": [],
                   "sampling": False, "completion": False},
        "servers": {}, "spool": "/var/perch/spool/mcp.jsonl",
        "quarantined": False, "auth_token": TOKEN,
    }
    probe_path = os.path.join(work, "probe.py")
    with open(probe_path, "w") as f:
        f.write(_PROBE)

    print("launching gateway container via DockerBackend.ensure_mcp_gateway ...")
    try:
        b.ensure_network(PROJECT)
        b.ensure_mcp_gateway(PROJECT, SERVICE, "python:3.12-slim", config, spool_dir)
        time.sleep(2)
        running = _docker("inspect", "-f", "{{.State.Running}}", cname, check=False).stdout.strip()
        print(f"gateway container running: {running}")
        url = f"http://{cname}:{mediation.GATEWAY_PORT}/"
        probe = _docker("run", "--rm", "--network", internal_net,
                        "-v", f"{probe_path}:/probe.py:ro",
                        "python:3.12-slim", "python", "/probe.py", url, TOKEN, check=False)
        sys.stdout.write(probe.stdout)
        sys.stderr.write(probe.stderr)
        ok = probe.returncode == 0
    finally:
        _docker("rm", "-f", cname, check=False)
        _docker("network", "rm", egress.main_network(PROJECT), internal_net, check=False)

    print("\n==== docker gateway check:", "PASS ====" if ok else "FAIL ====")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(run())
