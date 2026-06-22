"""
perch -- a tiny, friendly way to host your own apps and agents.

  perch doctor                       # check Docker & co. are ready (start here)
  perch up                           # set up if needed, then bring everything online
  perch init                         # write a starter perch.yaml
  perch plan                         # dry run: show the diff
  perch apply [--rebuild]            # converge your host to the manifest
  perch status                       # what's running
  perch logs <service> [-f]          # tail a service
  perch drift                        # read-only posture check (exits 2 on drift)
  perch run <service>                # one-shot run (handy for agents)
  perch proxy                        # generate + run the HTTPS reverse proxy
  perch scheduler                    # foreground loop: cron agents + scheduled backups
  perch backup [service]             # dump managed postgres service(s)
  perch restore <service> <file>     # restore a postgres service from a dump
  perch serve                        # run the web console + API (http://127.0.0.1:8787)
  perch destroy                      # remove everything in the manifest
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import backups
from .docker_backend import DockerBackend, DockerError
from .manifest import Manifest
from .proxy import caddyfile, has_routes
from .reconcile import Reconciler

STARTER = """\
project: my-stack

defaults:
  restart: unless-stopped

services:
  - name: web
    type: webapp
    build:
      context: ./examples/hello-web
    port: 8080
    route:
      host: web.localhost
    env:
      - { key: GREETING, value: "hello from perch" }

  # An agent is just a long-lived (or scheduled) worker.
  # - name: my-agent
  #   type: agent
  #   build: { context: https://github.com/you/your-agent }
  #   schedule: "0 */6 * * *"        # omit to run continuously
  #   env:
  #     - { key: ANTHROPIC_API_KEY, value: "${ANTHROPIC_API_KEY}", secret: true }
"""


def _load(path: str) -> Manifest:
    if not Path(path).exists():
        sys.exit(f"{path} not found -- run `perch init` first")
    return Manifest.load(path)


def cmd_init(args) -> int:
    if Path(args.file).exists() and not args.force:
        sys.exit(f"{args.file} already exists (use --force to overwrite)")
    Path(args.file).write_text(STARTER)
    print(f"wrote {args.file}")
    return 0


def cmd_plan(args) -> int:
    m = _load(args.file)
    rec = Reconciler(DockerBackend(), m, force_rebuild=args.rebuild)
    plan = rec.plan()
    print(f"plan for '{m.project}': {len(plan)} action(s)")
    for a in plan:
        print(f"  {rec.icon(a.kind)} {a.kind:<12} {a.target:<22} {a.detail}")
    return 0


def cmd_apply(args) -> int:
    m = _load(args.file)
    rec = Reconciler(DockerBackend(), m, force_rebuild=args.rebuild)
    plan = rec.plan()
    changes = [a for a in plan if a.kind != "noop"]
    print(f"apply for '{m.project}': {len(changes)} change(s)")
    for a in plan:
        print(f"  {rec.icon(a.kind)} {a.kind:<12} {a.target:<22} {a.detail}")
    if not changes:
        return 0
    if not args.yes and input("\nproceed? [y/N] ").strip().lower() != "y":
        return 1
    rec.apply(on_action=lambda a: a.kind != "noop" and print(f"  -> {a.kind} {a.target}"))
    print("done.")
    return 0


def cmd_status(args) -> int:
    m = _load(args.file)
    for ls in DockerBackend().list_managed(m.project):
        health = "" if ls.health in (None, "none") else f"({ls.health})"
        print(f"  {ls.name:<22} {ls.status:<10} {health}")
    return 0


def cmd_logs(args) -> int:
    m = _load(args.file)
    for line in DockerBackend().logs(m.project, args.service, follow=args.follow):
        print(line)
    return 0


def cmd_drift(args) -> int:
    m = _load(args.file)
    report = Reconciler(DockerBackend(), m).drift()
    if not report:
        print("no drift: host matches the manifest.")
        return 0
    print(f"{len(report)} finding(s):")
    for line in report:
        print(f"  {line}")
    return 2


def cmd_run(args) -> int:
    m = _load(args.file)
    rec = Reconciler(DockerBackend(), m)
    svc = m.by_name().get(args.service)
    if not svc:
        sys.exit(f"no service named '{args.service}'")
    try:
        rec._check_supply_chain(svc)              # C12: don't run a disallowed image
    except ValueError as e:
        sys.exit(str(e))
    DockerBackend().ensure_network(m.project)
    code = DockerBackend().run_once(svc, rec._ctx(svc, mint=True))
    print(f"{args.service} exited with {code}")
    return code


def cmd_proxy(args) -> int:
    m = _load(args.file)
    if not has_routes(m):
        print("no services define route.host -- nothing to proxy.")
        return 0
    out = Path("Caddyfile")
    out.write_text(caddyfile(m))
    print(f"wrote {out}")
    if args.generate_only:
        return 0
    net = DockerBackend().ensure_network(m.project)
    subprocess.run(["docker", "rm", "-f", f"perch-{m.project}-proxy"], capture_output=True)
    subprocess.run([
        "docker", "run", "-d", "--name", f"perch-{m.project}-proxy",
        "--network", net, "--restart", "unless-stopped",
        "--label", "perch.managed=true",
        "--label", f"perch.project={m.project}",
        "--label", "perch.service=proxy",
        "-p", "80:80", "-p", "443:443",
        "-v", f"{out.resolve()}:/etc/caddy/Caddyfile:ro",
        "-v", f"perch-{m.project}-caddy-data:/data",
        "caddy:2",
    ], check=True)
    print("proxy running on :80 and :443")
    return 0


def _backup_one(backend: DockerBackend, m, svc) -> None:
    out = backups.new_backup_path(".perch", m.project, svc.name)
    backend.dump_postgres(m.project, svc.name, str(out))
    retain = (svc.backup or {}).get("retain", 7)
    kept = backups.prune(".perch", m.project, svc.name, retain)
    print(f"  backed up {svc.name} -> {out.name} ({len(kept)} retained)")


def cmd_backup(args) -> int:
    m = _load(args.file)
    backend = DockerBackend()
    targets = [s for s in m.services if s.type == "postgres"
               and (args.service is None or s.name == args.service)]
    if not targets:
        print("no postgres services to back up.")
        return 0
    for svc in targets:
        _backup_one(backend, m, svc)
    return 0


def cmd_restore(args) -> int:
    m = _load(args.file)
    if not Path(args.file_path).exists():
        sys.exit(f"backup file not found: {args.file_path}")
    code = DockerBackend().restore_postgres(m.project, args.service, args.file_path)
    print("restore complete." if code == 0 else f"restore exited with {code}")
    return code


def cmd_scheduler(args) -> int:
    """Foreground loop: runs cron-scheduled agents and managed-service backups.
    Wrap in systemd/supervisor for production."""
    m = _load(args.file)
    backend = DockerBackend()
    rec = Reconciler(backend, m)
    scheduled = [s for s in m.services if s.schedule]
    backup_jobs = [s for s in m.services
                   if s.type == "postgres" and (s.backup or {}).get("schedule")]
    if not scheduled and not backup_jobs:
        print("no scheduled services or backups. nothing to do.")
        return 0
    labels = [s.name for s in scheduled] + [f"{s.name}(backup)" for s in backup_jobs]
    print(f"scheduler up: {', '.join(labels)} (ctrl-c to stop)")
    backend.ensure_network(m.project)
    last_minute = None
    while True:
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        if now != last_minute:
            last_minute = now
            for svc in scheduled:
                if cron_matches(svc.schedule, now):
                    try:
                        rec._check_supply_chain(svc)      # C12: skip a disallowed image
                    except ValueError as e:
                        print(f"[{now:%H:%M}] BLOCKED {svc.name}: {e}")
                        continue
                    print(f"[{now:%H:%M}] running {svc.name}")
                    backend.run_once(svc, rec._ctx(svc, mint=True))
            for svc in backup_jobs:
                if cron_matches(svc.backup["schedule"], now):
                    print(f"[{now:%H:%M}] backing up {svc.name}")
                    _backup_one(backend, m, svc)
        time.sleep(5)


# ---- minimal 5-field cron matcher (no external deps) --------------------
def _field(expr: str, value: int, lo: int, hi: int) -> bool:
    for part in expr.split(","):
        if part == "*":
            return True
        if part.startswith("*/"):
            if value % int(part[2:]) == 0:
                return True
        elif "-" in part:
            a, b = part.split("-")
            if int(a) <= value <= int(b):
                return True
        elif part.isdigit() and int(part) == value:
            return True
    return False


def cron_matches(expr: str, when: datetime) -> bool:
    mi, hr, dom, mon, dow = expr.split()
    return (_field(mi, when.minute, 0, 59) and _field(hr, when.hour, 0, 23)
            and _field(dom, when.day, 1, 31) and _field(mon, when.month, 1, 12)
            and _field(dow, when.weekday() == 6 and 0 or when.weekday() + 1, 0, 6))


def _port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def cmd_doctor(args) -> int:
    """Plain-English check that everything Perch needs is in place."""
    ok = True

    def check(label: str, passed: bool, fix: str) -> None:
        nonlocal ok
        mark = "OK  " if passed else "X   "
        print(f"  {mark} {label}")
        if not passed:
            ok = False
            print(f"       -> {fix}")

    py = sys.version_info
    check(f"Python {py.major}.{py.minor} (need 3.10+)", py >= (3, 10),
          "Install a newer Python from python.org, then reinstall Perch.")

    has_docker = shutil.which("docker") is not None
    check("Docker is installed", has_docker,
          "Install Docker Desktop (Mac/Windows) or run: curl -fsSL https://get.docker.com | sh  (Linux)")

    daemon = False
    if has_docker:
        daemon = subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    check("Docker is running", daemon,
          "Open Docker Desktop and wait for it to say 'running', then try again.")

    p80, p443 = _port_free(80), _port_free(443)
    check("Port 80 is free (for the web address)", p80,
          "Something else is using port 80. Stop it, or skip `perch proxy` and use the direct container.")
    check("Port 443 is free (for HTTPS)", p443,
          "Something else is using port 443. Stop it before running `perch proxy`.")

    print()
    print("All good -- run `perch up`." if ok else "Fix the items marked X above, then run `perch doctor` again.")
    return 0 if ok else 1


def cmd_up(args) -> int:
    """The one-button path: set up if needed, then bring everything online."""
    # 1. quick prerequisite gate
    if shutil.which("docker") is None or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("Docker isn't ready yet. Run `perch doctor` to see exactly what to fix.")
        return 1
    # 2. make a manifest if there isn't one
    if not Path(args.file).exists():
        Path(args.file).write_text(STARTER)
        print(f"Created {args.file} with a sample app. Edit it any time to add your own.")
    m = _load(args.file)
    rec = Reconciler(DockerBackend(), m, force_rebuild=args.rebuild)
    # 3. apply
    changes = [a for a in rec.plan() if a.kind != "noop"]
    if changes:
        print(f"Bringing up '{m.project}'...")
        rec.apply(on_action=lambda a: a.kind != "noop" and print(f"  -> {a.kind} {a.target}"))
    else:
        print("Everything is already up to date.")
    # 4. proxy + show URLs
    if has_routes(m):
        cmd_proxy(argparse.Namespace(file=args.file, generate_only=False))
        print("\nYour apps are live at:")
        for svc in m.services:
            if svc.route.host:
                print(f"  http://{svc.route.host}")
    else:
        print("\nDone. (No `route.host` set, so nothing is exposed on a URL yet.)")
    return 0


def cmd_serve(args) -> int:
    from .api import serve
    serve(manifest_path=args.file, host=args.host, port=args.port,
          require_auth=args.require_auth)
    return 0


def cmd_destroy(args) -> int:
    m = _load(args.file)
    if not args.yes and input(f"destroy ALL of '{m.project}'? [y/N] ").strip().lower() != "y":
        return 1
    b = DockerBackend()
    for ls in b.list_managed(m.project):
        b.remove(m.project, ls.name)
        print(f"  - {ls.name}")
    return 0


def cmd_mcp_config(args) -> int:
    """Print the MCP client config that points an agent at its mediating gateway (C9).
    Drop the output into the agent's MCP client config so every tool call is brokered."""
    m = _load(args.file)
    svc = m.by_name().get(args.service)
    if svc is None:
        sys.exit(f"no service named {args.service!r} in {args.file}")
    if not svc.mcp_enabled:
        sys.exit(f"service {args.service!r} has no `mcp:` block -- nothing to mediate")
    from . import mediation
    from .state import State
    token = State().secret(m.project, svc.name, "mcp_token") if svc.mcp_auth else None
    print(json.dumps(mediation.gateway_client_config(m.project, svc.name, token), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="perch", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-f", "--file", default="perch.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").add_argument("--force", action="store_true")
    su = sub.add_parser("up", help="set up if needed, then bring everything online")
    su.add_argument("--rebuild", action="store_true")
    sub.add_parser("doctor", help="check that Docker and everything else is ready")
    sp = sub.add_parser("plan"); sp.add_argument("--rebuild", action="store_true")
    sa = sub.add_parser("apply")
    sa.add_argument("--rebuild", action="store_true")
    sa.add_argument("-y", "--yes", action="store_true")
    sub.add_parser("status")
    sl = sub.add_parser("logs"); sl.add_argument("service"); sl.add_argument("-f", "--follow", action="store_true")
    sub.add_parser("drift")
    sr = sub.add_parser("run"); sr.add_argument("service")
    spx = sub.add_parser("proxy"); spx.add_argument("--generate-only", action="store_true")
    sub.add_parser("scheduler")
    sbk = sub.add_parser("backup", help="dump managed postgres services")
    sbk.add_argument("service", nargs="?", default=None)
    srs = sub.add_parser("restore", help="restore a postgres service from a dump")
    srs.add_argument("service"); srs.add_argument("file_path")
    ssv = sub.add_parser("serve", help="run the web console + API")
    ssv.add_argument("--host", default="127.0.0.1"); ssv.add_argument("--port", type=int, default=8787)
    ssv.add_argument("--require-auth", action="store_true",
                     help="require a bearer token (PERCH_API_TOKENS / .perch/api_tokens.json)")
    sd = sub.add_parser("destroy"); sd.add_argument("-y", "--yes", action="store_true")
    smc = sub.add_parser("mcp-config",
                         help="print the MCP client config that points an agent at its gateway (C9)")
    smc.add_argument("service")

    args = p.parse_args(argv)
    dispatch = {
        "init": cmd_init, "up": cmd_up, "doctor": cmd_doctor,
        "plan": cmd_plan, "apply": cmd_apply, "status": cmd_status,
        "logs": cmd_logs, "drift": cmd_drift, "run": cmd_run, "proxy": cmd_proxy,
        "scheduler": cmd_scheduler, "backup": cmd_backup, "restore": cmd_restore,
        "serve": cmd_serve, "destroy": cmd_destroy, "mcp-config": cmd_mcp_config,
    }
    try:
        return dispatch[args.cmd](args)
    except DockerError as e:
        sys.exit(f"docker: {e}")
    except KeyError as e:
        sys.exit(f"missing secret: {e}")


if __name__ == "__main__":
    raise SystemExit(main())
