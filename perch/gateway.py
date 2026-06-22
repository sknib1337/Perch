"""
C9 -- the mediating MCP gateway (a per-agent sidecar; the runtime enforcement point).

The agent's MCP client points at this process (`PERCH_MCP_GATEWAY`). For every
message it authorizes against the agent's `MediationPolicy` (perch/mediation.py),
forwards only what's allowed to the configured upstream MCP servers, filters list
responses down to the allowlist, and appends each decision to a spool the reconciler
folds into the C10/C11 tamper-evident audit + quarantine loop. Combined with C8
egress -- the agent's only outbound path is this gateway -- the agent cannot route
around it.

Run it standalone (this is what the container does):
    python -m perch.gateway /etc/perch/gateway.json

Config (written by the reconciler, mounted read-only):
    {"project","service","subject","port",
     "policy": <MediationPolicy.to_config()>,
     "servers": {"github": {"transport":"http","url":"https://..."},
                 "fs": {"transport":"stdio","command":["python","-m","mcp_server_fs","/data"]}},
     "spool": "/var/perch/spool/mcp.jsonl"}

Design: the security core (`Gateway.handle_payload`) is pure and offline-tested with
a fake upstream; the HTTP/stdio transports are thin and fail closed. Routing: a tool
is `server.tool` and a prompt is `server.prompt` (the segment before the first dot
selects the upstream); a resource URI's scheme selects the upstream. `*/list` is
aggregated across upstreams, name-prefixed, then filtered to the allowlist.

v1 limitations (documented, not hidden): server->agent streaming (SSE) and
server-initiated `sampling/createMessage` over a reverse channel are not proxied --
they are denied by policy default and only mediated if they traverse the request
path. The authorization + audit guarantees hold regardless.
"""

from __future__ import annotations

import hmac
import json
import subprocess
import sys
import threading
import time
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import mcp as mcp_mod
from .mediation import GATEWAY_PORT, MediationDecision, MediationPolicy, audit_record

_CLIENT_INFO = {"name": "perch-mcp-gateway", "version": "1"}
_PROTOCOL_VERSION = "2025-06-18"
_UPSTREAM_TIMEOUT = 30          # seconds; a stalled upstream fails closed, never hangs the agent


def _bearer(headers) -> "str | None":
    """The presented gateway token: `Authorization: Bearer <t>` or `X-Perch-Token`."""
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip() or None
    return headers.get("X-Perch-Token", "").strip() or None


def _token_ok(expected: "str | None", presented: "str | None") -> bool:
    """Constant-time check. With no expected token (None) auth is disabled (allow); an
    empty-string expected token is NOT "disabled" -- it denies, closed. Compare as
    bytes: a non-ASCII header value makes `compare_digest` raise on str (HTTP headers
    decode latin-1), which would crash the request thread instead of a clean 401."""
    if expected is None:
        return True
    if not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


class GatewayError(Exception):
    """An upstream/routing failure. Surfaced to the agent as a JSON-RPC error so a
    failure never silently bypasses the gateway."""


def _parse_http_body(ctype: str, raw: bytes) -> dict:
    """Parse an MCP-over-HTTP response. Plain `application/json` is loaded directly;
    a Streamable-HTTP `text/event-stream` (SSE) response carries the JSON-RPC message
    in `data:` field(s) -- common for hosted MCP servers -- so extract that. Multi-event
    streaming (server-initiated messages) is out of scope: we return the response
    message (the event bearing a result/error)."""
    text = raw.decode("utf-8", "replace")
    is_sse = "text/event-stream" in ctype.lower() or text.lstrip().startswith(("event:", "data:", ":"))
    if not is_sse:
        try:
            return json.loads(text)
        except ValueError as e:
            raise GatewayError(f"http upstream returned non-JSON: {e}") from e
    events, buf = [], []
    for line in text.splitlines():
        if line.startswith("data:"):
            buf.append(line[5:].lstrip())
        elif not line.strip():               # blank line terminates one SSE event
            if buf:
                events.append("\n".join(buf)); buf = []
    if buf:
        events.append("\n".join(buf))
    parsed = []
    for ev in events:
        try:
            parsed.append(json.loads(ev))
        except ValueError:
            continue
    for p in parsed:                         # prefer the JSON-RPC response message
        if isinstance(p, dict) and ("result" in p or "error" in p):
            return p
    if parsed:
        return parsed[0]
    raise GatewayError("SSE upstream had no parseable JSON data")


# ---- upstream transports (thin; fail closed) ----------------------------
class HttpUpstream:
    def __init__(self, url: str):
        self.url = url
        self._session: "str | None" = None
        self._ready = False
        self._lock = threading.Lock()

    def _post(self, message: dict) -> dict:
        u = urlparse(self.url)
        conn_cls = HTTPSConnection if u.scheme == "https" else HTTPConnection
        conn = conn_cls(u.hostname, u.port, timeout=_UPSTREAM_TIMEOUT)
        try:
            headers = {"Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream"}
            if self._session:
                headers["Mcp-Session-Id"] = self._session
            conn.request("POST", u.path or "/", json.dumps(message), headers)
            resp = conn.getresponse()
            sid = resp.getheader("Mcp-Session-Id")
            if sid:
                self._session = sid
            ctype = resp.getheader("Content-Type", "")
            raw = resp.read()
        except OSError as e:
            raise GatewayError(f"http upstream unreachable: {e}") from e
        finally:
            conn.close()
        if not raw:
            return {}
        return _parse_http_body(ctype, raw)

    def _ensure_ready(self) -> None:
        if self._ready:
            return
        with self._lock:
            if self._ready:
                return
            self._post({"jsonrpc": "2.0", "id": "perch-init", "method": "initialize",
                        "params": {"protocolVersion": _PROTOCOL_VERSION,
                                   "capabilities": {}, "clientInfo": _CLIENT_INFO}})
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self._ready = True

    def send(self, message: dict) -> dict:
        self._ensure_ready()
        return self._post(message)


class StdioUpstream:
    """An MCP stdio server run as a subprocess. Framing is newline-delimited JSON
    (current MCP stdio transport: one JSON-RPC message per line, no embedded newlines)."""

    def __init__(self, command: list):
        self.command = [str(c) for c in command]
        self._proc: "subprocess.Popen | None" = None
        self._ready = False
        self._lock = threading.Lock()

    def _spawn(self) -> None:
        self._proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._send_line({"jsonrpc": "2.0", "id": "perch-init", "method": "initialize",
                         "params": {"protocolVersion": _PROTOCOL_VERSION,
                                    "capabilities": {}, "clientInfo": _CLIENT_INFO}})
        self._read_line()
        self._send_line({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _kill(self) -> None:
        if self._proc is not None:
            try:
                self._proc.kill()
            except OSError:
                pass
        self._proc = None
        self._ready = False

    def _send_line(self, message: dict) -> None:
        if not (self._proc and self._proc.stdin):
            raise GatewayError("stdio upstream not running")
        try:
            self._proc.stdin.write(json.dumps(message) + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError) as e:               # dead/closed pipe -> fail closed
            raise GatewayError(f"stdio upstream write failed: {e}") from e

    def _read_line(self) -> dict:
        if not (self._proc and self._proc.stdout):
            raise GatewayError("stdio upstream not running")
        # Read on a watchdog thread so a stalled server can never hold the lock (and
        # the agent) indefinitely; on timeout the subprocess is killed so the next
        # call respawns rather than inheriting a desynced pipe.
        out: list = []
        t = threading.Thread(target=lambda: out.append(self._proc.stdout.readline()), daemon=True)
        t.start()
        t.join(_UPSTREAM_TIMEOUT)
        if t.is_alive():
            self._kill()
            raise GatewayError("stdio upstream timed out")
        line = out[0] if out else ""
        if not line:
            raise GatewayError("stdio upstream closed")
        try:
            return json.loads(line)
        except ValueError as e:
            raise GatewayError(f"stdio upstream returned non-JSON: {e}") from e

    def send(self, message: dict) -> dict:
        with self._lock:
            try:
                if not self._ready:
                    self._spawn()
                    self._ready = True
                self._send_line(message)
                if "id" not in message:          # a notification has no response
                    return {}
                return self._read_line()
            except GatewayError:
                self._kill()                     # desynced/failed -> respawn next time
                raise
            except OSError as e:
                self._kill()
                raise GatewayError(f"stdio upstream failed: {e}") from e


class Upstreams:
    """Routes a server name to its transport. Unknown server -> fail closed."""

    def __init__(self, servers: dict):
        self._by_name: dict = {}
        for name, spec in (servers or {}).items():
            spec = spec or {}
            if spec.get("transport") == "stdio":
                self._by_name[name] = StdioUpstream(spec.get("command", []))
            else:
                self._by_name[name] = HttpUpstream(spec.get("url", ""))

    def names(self) -> list:
        return list(self._by_name.keys())

    def send(self, server: str, message: dict) -> dict:
        up = self._by_name.get(server)
        if up is None:
            raise GatewayError(f"no upstream server {server!r} configured")
        return up.send(message)


# ---- the gateway core (pure; offline-tested with a fake Upstreams) -------
class Gateway:
    def __init__(self, *, project: str, service: str, subject: str,
                 policy: MediationPolicy, upstreams, spool=None, quarantined: bool = False,
                 auth_token: "str | None" = None, clock=time.time):
        self.project = project
        self.service = service
        self.subject = subject
        self.policy = policy
        self.upstreams = upstreams
        self.spool = spool
        self.quarantined = quarantined         # C11: this agent's subject is quarantined -> deny all
        self.auth_token = auth_token           # C1: per-agent bearer; None disables (see _token_ok)
        self.clock = clock

    # entry point: a parsed JSON payload (single message or a batch array)
    def handle_payload(self, payload):
        if isinstance(payload, list):
            if len(payload) > mcp_mod.MAX_BATCH_ELEMENTS:
                return [mcp_mod.jsonrpc_error(None,
                        f"perch: batch too large (max {mcp_mod.MAX_BATCH_ELEMENTS})")]
            out = [self._handle_one(m) for m in payload]   # each isolated (see _handle_one)
            out = [r for r in out if r is not None]
            return out or None                         # all-notifications batch -> no body
        return self._handle_one(payload)

    def _handle_one(self, message):
        med = mcp_mod.mediate(message, self.policy)
        if self.quarantined and med.allowed:           # a quarantined agent gets nothing
            med = mcp_mod.Mediation(med.method, med.target, False, "subject quarantined",
                                    rpc_id=med.rpc_id, is_request=med.is_request)
        self._spool(med)
        if not med.allowed:
            if med.is_request:
                return mcp_mod.jsonrpc_error(med.rpc_id, f"perch: {med.reason}")
            return None
        try:
            return self._dispatch(message, med)
        except Exception as e:                         # never bypass mediation or abort a batch
            reason = str(e) if isinstance(e, GatewayError) else "internal error"
            if med.is_request:
                return mcp_mod.jsonrpc_error(med.rpc_id, f"perch gateway: {reason}")
            return None

    def _ok(self, med, result) -> dict:
        return {"jsonrpc": mcp_mod.JSONRPC_VERSION, "id": med.rpc_id, "result": result}

    def _dispatch(self, message, med):
        method = med.method
        if not med.is_request:
            self._forward_notification(message, med)
            return None
        if method == "initialize":
            return self._ok(med, self._initialize_result(message))
        if method == "ping":
            return self._ok(med, {})
        if med.filter:                                 # tools/resources/prompts list
            return self._ok(med, self._aggregate_list(med.filter))
        server = self._server_of(med)
        resp = self.upstreams.send(server, self._rewrite(message, med))
        if isinstance(resp, dict):                     # pass the upstream response back under the agent's id
            resp = {**resp, "id": med.rpc_id}
        return resp

    # routing -------------------------------------------------------------
    def _server_of(self, med) -> str:
        if med.method in ("tools/call", "prompts/get"):
            return med.target.split(".", 1)[0]
        if med.method.startswith("resources/"):
            return med.target.split("://", 1)[0]
        raise GatewayError(f"no route for method {med.method!r}")

    def _rewrite(self, message, med) -> dict:
        """Strip the routing prefix so the upstream sees its native name; keep id."""
        if med.method not in ("tools/call", "prompts/get"):
            return message
        bare = med.target.split(".", 1)[1] if "." in med.target else med.target
        params = dict(message.get("params") or {})
        params["name"] = bare
        return {**message, "params": params}

    def _aggregate_list(self, capability: str) -> dict:
        method = {"tools": "tools/list", "resources": "resources/list",
                  "prompts": "prompts/list"}[capability]
        key = capability
        merged: list = []
        for server in self.upstreams.names():
            try:
                resp = self.upstreams.send(server, {"jsonrpc": "2.0", "id": f"perch-list-{server}",
                                                    "method": method, "params": {}})
            except GatewayError:
                continue                                # a dead upstream just contributes nothing
            items = (resp.get("result") or {}).get(key) if isinstance(resp, dict) else None
            for it in (items or []):
                if not isinstance(it, dict):
                    continue
                it = dict(it)
                if capability in ("tools", "prompts"):  # prefix bare name -> server.name
                    it["name"] = f"{server}.{it.get('name', '')}"
                merged.append(it)
        # filter the aggregated list to what the policy allows
        if capability == "tools":
            keep = lambda it: self.policy.authorized_tool(it.get("name", ""))
        elif capability == "prompts":
            keep = lambda it: self.policy.authorized_prompt(it.get("name", ""))
        else:
            keep = lambda it: self.policy.authorized_resource(it.get("uri", ""))
        return {key: [it for it in merged if keep(it)]}

    def _forward_notification(self, message, med) -> None:
        # Only route notifications that carry a routable target; others are dropped
        # (we never broadcast an agent notification to every upstream).
        routable = med.method in ("tools/call", "prompts/get") or med.method.startswith("resources/")
        if routable and med.target:
            try:
                self.upstreams.send(self._server_of(med), self._rewrite(message, med))
            except GatewayError:
                pass

    def _initialize_result(self, message) -> dict:
        params = message.get("params") or {}
        return {"protocolVersion": params.get("protocolVersion", _PROTOCOL_VERSION),
                "serverInfo": _CLIENT_INFO,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}}}

    # audit spool ---------------------------------------------------------
    def _spool(self, med) -> None:
        if not self.spool:
            return
        rec = audit_record(self.subject,
                           MediationDecision(med.target or med.method, med.allowed, med.reason),
                           at=int(self.clock()))
        rec["method"] = med.method
        try:
            with open(self.spool, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
        except OSError:
            pass                                        # never let spooling break mediation


# ---- HTTP front + entrypoint --------------------------------------------
def make_handler(gw: Gateway):
    class Handler(BaseHTTPRequestHandler):
        timeout = _UPSTREAM_TIMEOUT                      # drop a slow/partial-body client (Slowloris)

        def log_message(self, *a):                      # quiet
            pass

        def _send(self, obj, code=200):
            body = b"" if obj is None else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send({"ok": True})
            return self._send({"error": "not found"}, 404)

        def do_POST(self):
            if not _token_ok(gw.auth_token, _bearer(self.headers)):   # C1: per-agent bearer
                return self._send(mcp_mod.jsonrpc_error(None, "perch: unauthorized"), 401)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                return self._send(mcp_mod.jsonrpc_error(None, "perch: invalid Content-Length"), 400)
            if length < 0:                              # a negative length would make read() unbounded
                return self._send(mcp_mod.jsonrpc_error(None, "perch: invalid Content-Length"), 400)
            if length > mcp_mod.MAX_MESSAGE_BYTES:
                return self._send(mcp_mod.jsonrpc_error(None, "perch: message too large"), 413)
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw or b"{}")
            except ValueError:
                return self._send(mcp_mod.jsonrpc_error(
                    None, "perch: malformed JSON", code=mcp_mod.PARSE_ERROR_CODE), 400)
            try:
                result = gw.handle_payload(payload)
            except Exception:                           # last-resort net: never 500-leak, never bypass
                result = mcp_mod.jsonrpc_error(None, "perch gateway: internal error")
            return self._send(result)

    return Handler


def gateway_from_config(cfg: dict, upstreams=None) -> Gateway:
    return Gateway(
        project=cfg.get("project", ""), service=cfg.get("service", ""),
        subject=cfg.get("subject", ""),
        policy=MediationPolicy.from_config(cfg.get("policy", {})),
        upstreams=upstreams if upstreams is not None else Upstreams(cfg.get("servers", {})),
        spool=cfg.get("spool"), quarantined=bool(cfg.get("quarantined", False)),
        auth_token=cfg.get("auth_token"))


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m perch.gateway <config.json>", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8-sig") as f:    # tolerate a BOM on the mounted config
        cfg = json.load(f)
    gw = gateway_from_config(cfg)
    port = int(cfg.get("port", GATEWAY_PORT))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), make_handler(gw))
    print(f"perch mcp gateway for {cfg.get('service')!r} on :{port} "
          f"({len(gw.upstreams.names())} upstream(s))", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
