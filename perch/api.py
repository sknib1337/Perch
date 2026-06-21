"""
Perch HTTP API + static console host.

A dependency-light (stdlib only) read/write API over the existing control plane:
Reconciler (plan/drift/apply), DockerBackend (status/logs/backup), Manifest, and
the managed-service catalog. It also serves the web console from perch/web/.

Design notes:
- All secret values are masked. Never returns resolved ${VAR} values or
  managed-service credentials in clear text -- only key names.
- Binds 127.0.0.1 by default. It is unauthenticated; do not expose it directly.
  Put it behind the Perch proxy + auth, or an SSH tunnel, before remote use.
- Docker-dependent calls degrade gracefully (empty/`error` fields) so the console
  still renders a useful diagnostic state on a host where Docker isn't running.

The data-assembly methods on PerchAPI are pure and backend-injectable, so they
are unit-tested without Docker.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import backups as backups_mod
from . import catalog
from .docker_backend import DockerBackend
from .manifest import Manifest
from .reconcile import Reconciler
from .state import State

WEB_DIR = Path(__file__).parent / "web"
MASK = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"


class PerchAPI:
    def __init__(self, manifest: Manifest, backend=None, state: State | None = None):
        self.m = manifest
        self.b = backend or DockerBackend()
        self.state = state or State()
        self.rec = Reconciler(self.b, self.m, state=self.state)

    # ---- helpers --------------------------------------------------------
    def _live(self) -> dict:
        try:
            return {ls.name: ls for ls in self.b.list_managed(self.m.project)}
        except Exception:                       # Docker not available
            return {}

    def _service_dict(self, svc, live: dict | None = None) -> dict:
        live = live if live is not None else self._live()
        ls = live.get(svc.name)
        env = [{"key": e.key, "secret": e.secret,
                "value": MASK if e.secret else e.value} for e in svc.env]
        d = {
            "name": svc.name, "type": svc.type, "managed": svc.is_managed,
            "port": svc.port, "schedule": svc.schedule,
            "route": {"host": svc.route.host, "path": svc.route.path},
            "bindings": list(svc.bindings),
            "build": (svc.build.context if svc.build else None),
            "image": svc.image, "env": env,
            "security": svc.security, "resources": svc.resources,
            "restart": svc.restart, "volumes": svc.volumes,
            "status": getattr(ls, "status", "missing"),
            "health": getattr(ls, "health", "none"),
            "image_ref": getattr(ls, "image", None),
            "source_hash": getattr(ls, "source_hash", None),
            "config_hash": getattr(ls, "config_hash", None),
        }
        if svc.type == "postgres":
            d.update({"version": svc.version, "extensions": svc.extensions,
                      "backup": svc.backup})
        if svc.type == "storage":
            d["buckets"] = svc.buckets
        if svc.type == "rest-api":
            d["database"] = svc.database
        return d

    def _exports_masked(self, svc) -> dict:
        try:
            keys = list(catalog.exports_for(svc, self.m.project, self.state).keys())
        except Exception:
            keys = []
        # show host/port/url shape but mask credential-bearing values
        out = {}
        for k in keys:
            out[k] = MASK if any(t in k for t in ("PASSWORD", "SECRET", "URL", "KEY")) else "set"
        return out

    # ---- endpoints ------------------------------------------------------
    def project(self) -> dict:
        managed = [s.name for s in self.m.services if s.is_managed]
        workloads = [s.name for s in self.m.services if not s.is_managed]
        return {"project": self.m.project, "prune": self.m.prune,
                "managed": managed, "workloads": workloads,
                "service_count": len(self.m.services)}

    def services(self) -> list[dict]:
        live = self._live()
        return [self._service_dict(s, live) for s in self.m.services]

    def service(self, name: str) -> dict | None:
        svc = self.m.by_name().get(name)
        if not svc:
            return None
        d = self._service_dict(svc)
        if svc.is_managed:
            d["exports"] = self._exports_masked(svc)
        d["bound_by"] = [s.name for s in self.m.services if name in s.bindings]
        return d

    def topology(self) -> dict:
        live = self._live()
        nodes = []
        for s in self.m.services:
            ls = live.get(s.name)
            nodes.append({
                "id": s.name, "name": s.name, "type": s.type,
                "managed": s.is_managed,
                "status": getattr(ls, "status", "missing"),
                "health": getattr(ls, "health", "none"),
            })
        edges = [{"from": s.name, "to": dep}
                 for s in self.m.services for dep in self.m.deps(s)]
        return {"nodes": nodes, "edges": edges}

    def plan(self) -> list[dict]:
        try:
            return [{"kind": a.kind, "target": a.target, "detail": a.detail}
                    for a in self.rec.plan()]
        except Exception as e:                  # noqa: BLE001
            return [{"kind": "error", "target": "-", "detail": str(e)}]

    def drift(self) -> list[dict]:
        try:
            out = []
            for line in self.rec.drift():
                code, _, rest = line.partition(" ")
                name, _, msg = rest.strip().partition(":")
                out.append({"code": code, "service": name.strip(), "message": msg.strip()})
            return out
        except Exception as e:                  # noqa: BLE001
            return [{"code": "ERROR", "service": "-", "message": str(e)}]

    def backups(self) -> list[dict]:
        out = []
        for s in self.m.services:
            if s.type != "postgres":
                continue
            d = backups_mod.backup_dir(".perch", self.m.project, s.name)
            if not d.exists():
                continue
            for f in sorted(d.glob("*.sql.gz"), reverse=True):
                st = f.stat()
                out.append({"service": s.name, "file": f.name, "size": st.st_size,
                            "created_at": int(st.st_mtime)})
        return out

    def doctor(self) -> list[dict]:
        import shutil, socket, subprocess
        checks = []
        py = sys.version_info
        checks.append({"check": f"Python {py.major}.{py.minor}", "ok": py >= (3, 10),
                       "fix": "Install Python 3.10+"})
        has_docker = shutil.which("docker") is not None
        checks.append({"check": "Docker installed", "ok": has_docker,
                       "fix": "Install Docker Desktop or get.docker.com"})
        daemon = (has_docker and
                  subprocess.run(["docker", "info"], capture_output=True).returncode == 0)
        checks.append({"check": "Docker running", "ok": daemon,
                       "fix": "Start Docker"})
        for port in (80, 443):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port)); free = True
            except OSError:
                free = False
            finally:
                s.close()
            checks.append({"check": f"Port {port} free", "ok": free,
                           "fix": f"Free port {port} for the proxy"})
        return checks

    # ---- write actions --------------------------------------------------
    def apply(self, rebuild: bool = False) -> dict:
        rec = Reconciler(self.b, self.m, force_rebuild=rebuild, state=self.state)
        applied = []
        try:
            rec.apply(on_action=lambda a: a.kind != "noop"
                      and applied.append({"kind": a.kind, "target": a.target}))
            return {"ok": True, "applied": applied}
        except Exception as e:                  # noqa: BLE001
            return {"ok": False, "error": str(e), "applied": applied}

    def restart(self, name: str) -> dict:
        try:
            self.b.restart(self.m.project, name); return {"ok": True}
        except Exception as e:                  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    def backup(self, name: str) -> dict:
        svc = self.m.by_name().get(name)
        if not svc or svc.type != "postgres":
            return {"ok": False, "error": "not a postgres service"}
        out = backups_mod.new_backup_path(".perch", self.m.project, name)
        try:
            self.b.dump_postgres(self.m.project, name, str(out))
            backups_mod.prune(".perch", self.m.project, name, (svc.backup or {}).get("retain", 7))
            return {"ok": True, "file": out.name}
        except Exception as e:                  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    def logs(self, name: str, tail: int = 200) -> dict:
        try:
            lines = list(self.b.logs(self.m.project, name, follow=False))
            return {"lines": lines[-tail:]}
        except Exception as e:                  # noqa: BLE001
            return {"lines": [], "error": str(e)}


# ---- HTTP layer ---------------------------------------------------------
def make_handler(api: PerchAPI):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, obj, code=200, ctype="application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _static(self, path: str):
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            f = (WEB_DIR / rel).resolve()
            if not str(f).startswith(str(WEB_DIR.resolve())) or not f.is_file():
                f = WEB_DIR / "index.html"
            ctype = ("text/html" if f.suffix == ".html"
                     else "application/javascript" if f.suffix == ".js"
                     else "text/css" if f.suffix == ".css" else "text/plain")
            self._send(f.read_bytes(), ctype=ctype)

        def do_GET(self):
            p = urlparse(self.path).path
            r = {
                "/api/project": api.project, "/api/services": api.services,
                "/api/topology": api.topology, "/api/plan": api.plan,
                "/api/drift": api.drift, "/api/backups": api.backups,
                "/api/doctor": api.doctor,
            }.get(p)
            if r:
                return self._send(r())
            if p.startswith("/api/services/") and p.endswith("/logs"):
                name = p.split("/")[3]
                return self._send(api.logs(name))
            if p.startswith("/api/services/"):
                name = p.split("/")[3]
                d = api.service(name)
                return self._send(d, 200 if d else 404) if d else self._send({"error": "not found"}, 404)
            return self._static(p)

        def do_POST(self):
            p = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            if p == "/api/apply":
                return self._send(api.apply(rebuild=bool(body.get("rebuild"))))
            if p.startswith("/api/services/") and p.endswith("/restart"):
                return self._send(api.restart(p.split("/")[3]))
            if p.startswith("/api/services/") and p.endswith("/backup"):
                return self._send(api.backup(p.split("/")[3]))
            return self._send({"error": "not found"}, 404)

    return Handler


def serve(manifest_path: str = "perch.yaml", host: str = "127.0.0.1", port: int = 8787) -> None:
    api = PerchAPI(Manifest.load(manifest_path))
    httpd = ThreadingHTTPServer((host, port), make_handler(api))
    print(f"Perch console on http://{host}:{port}  (project: {api.m.project})")
    print("Bound to localhost and unauthenticated -- do not expose directly.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
