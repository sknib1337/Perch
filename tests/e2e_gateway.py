"""
End-to-end integration check for the C9 MCP gateway -- REAL sockets, REAL subprocess.

This is intentionally NOT part of the fast offline suite (`python tests/test_reconcile.py`):
it binds localhost ports and launches the gateway as a subprocess. Run it explicitly:

    python tests/e2e_gateway.py

It runs the actual `perch.gateway` (the same code the container runs) against a real
plain-JSON HTTP MCP server, a real SSE/Streamable-HTTP MCP server, and a real stdio MCP
server, then acts as the agent over real HTTP and asserts that mediation, routing,
name-rewriting, list filtering, the stdio bridge, SSE parsing, and the decision spool
all work. No Docker required (it does not exercise the docker_backend launch wiring).
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATEWAY_PORT, ECHO_PORT, SSE_PORT = 8911, 9111, 9112
TOKEN = "sim-per-agent-token"

_STDIO_SERVER = '''
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if "id" not in msg:
        continue
    m = msg.get("method")
    if m == "initialize":
        r = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "files"}, "capabilities": {"tools": {}}}
    elif m == "tools/list":
        r = {"tools": [{"name": "read"}, {"name": "wipe"}]}
    elif m == "tools/call":
        r = {"content": [{"type": "text", "text": "stdio:%s ok" % (msg.get("params") or {}).get("name")}]}
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": r}) + "\\n")
    sys.stdout.flush()
'''

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


def _handler(server_name, tools, sse=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            msg = json.loads(self.rfile.read(n) or b"{}")
            method, mid = msg.get("method"), msg.get("id")
            if method == "initialize":
                result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": server_name},
                          "capabilities": {"tools": {}}}
            elif method == "tools/list":
                result = {"tools": [{"name": t} for t in tools]}
            elif method == "tools/call":
                tag = "via SSE " if sse else ""
                result = {"content": [{"type": "text",
                                       "text": f"{server_name}:{msg['params'].get('name')} {tag}ok"}]}
            else:
                result = {}
            if "id" not in msg:
                self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
                return
            rpc = json.dumps({"jsonrpc": "2.0", "id": mid, "result": result})
            if sse:
                body = (f"event: message\ndata: {rpc}\n\n").encode()
                ctype = "text/event-stream"
            else:
                body = rpc.encode()
                ctype = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def _serve(handler, port):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _rpc(method, params=None, mid=1, token=TOKEN):
    body = json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{GATEWAY_PORT}/", data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
    return json.loads(raw) if raw else None


def run() -> int:
    work = tempfile.mkdtemp(prefix="perch-e2e-")
    spool = os.path.join(work, "mcp.jsonl")
    stdio_path = os.path.join(work, "stdio_server.py")
    with open(stdio_path, "w") as f:
        f.write(_STDIO_SERVER)

    _serve(_handler("echo", ["say", "delete_everything"]), ECHO_PORT)
    _serve(_handler("sse", ["echo"], sse=True), SSE_PORT)

    cfg = {
        "project": "e2e", "service": "agent", "subject": "perch://e2e/agent/agent",
        "port": GATEWAY_PORT,
        "policy": {"tools": ["echo.say", "files.read", "sse.echo"],
                   "resources": [], "prompts": [], "sampling": False, "completion": False},
        "servers": {
            "echo": {"transport": "http", "url": f"http://127.0.0.1:{ECHO_PORT}/"},
            "sse": {"transport": "http", "url": f"http://127.0.0.1:{SSE_PORT}/"},
            "files": {"transport": "stdio", "command": [sys.executable, stdio_path]},
        },
        "spool": spool,
        "auth_token": TOKEN,
    }
    cfg_path = os.path.join(work, "gateway.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)

    gw = subprocess.Popen([sys.executable, "-m", "perch.gateway", cfg_path], cwd=REPO,
                          env=dict(os.environ, PYTHONPATH=REPO),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        last_err = None
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{GATEWAY_PORT}/healthz", timeout=1) as r:
                    if r.status == 200:
                        break
            except Exception as ex:
                last_err = ex
                time.sleep(0.2)
        else:
            print("readiness last error:", repr(last_err))
            gw.terminate()
            try:
                print("GATEWAY DID NOT START:\n", gw.communicate(timeout=3)[0])
            except Exception as ex:
                print("GATEWAY DID NOT START (no output):", ex)
            return 1
        print("gateway up; agent traffic over real HTTP\n")

        # C1: an unauthenticated request is rejected before any mediation/forwarding
        try:
            _rpc("tools/list", mid=99, token=None)
            check("unauthenticated request rejected (401)", False, "expected HTTP 401")
        except urllib.error.HTTPError as he:
            check("unauthenticated request rejected (401)", he.code == 401, f"got {he.code}")

        init = _rpc("initialize", {"protocolVersion": "2025-06-18"}, 1)
        check("initialize answered by gateway",
              init.get("result", {}).get("serverInfo", {}).get("name") == "perch-mcp-gateway")

        names = sorted(t["name"] for t in _rpc("tools/list", mid=2).get("result", {}).get("tools", []))
        check("tools/list aggregated + filtered to allowlist",
              names == ["echo.say", "files.read", "sse.echo"], f"got {names}")
        check("denied tool not advertised", "echo.delete_everything" not in names, f"got {names}")

        a = _rpc("tools/call", {"name": "echo.say", "arguments": {"text": "hi"}}, 3)
        check("allowed HTTP tool forwarded + executed",
              a.get("result", {}).get("content", [{}])[0].get("text") == "echo:say ok", f"got {a}")

        d = _rpc("tools/call", {"name": "echo.delete_everything"}, 4)
        check("denied HTTP tool blocked, not forwarded",
              "error" in d and d["error"]["code"] == -32001, f"got {d}")

        s = _rpc("tools/call", {"name": "files.read"}, 5)
        check("allowed STDIO tool forwarded + executed",
              s.get("result", {}).get("content", [{}])[0].get("text") == "stdio:read ok", f"got {s}")

        e = _rpc("tools/call", {"name": "sse.echo"}, 6)
        check("SSE/Streamable-HTTP upstream call works", "result" in e and "error" not in e, f"got {e}")

        time.sleep(0.3)
        recs = [json.loads(l) for l in open(spool)] if os.path.exists(spool) else []
        check("spool recorded an allowed decision", any(r["allowed"] and r["tool"] == "echo.say" for r in recs))
        check("spool recorded a denied decision",
              any(not r["allowed"] and r["tool"] == "echo.delete_everything" for r in recs))
    finally:
        gw.terminate()
        try:
            gw.wait(timeout=5)
        except Exception:
            gw.kill()

    print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
    if FAIL:
        print("FAILED:", ", ".join(FAIL))
    return 0 if not FAIL else 2


if __name__ == "__main__":
    raise SystemExit(run())
