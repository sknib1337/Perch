"""
Default backend: plain Docker via the `docker` CLI.

No daemon SDK, no magic -- every container is launched with explicit, readable
hardening flags so you can audit exactly what runs. Perch tracks ownership
and drift through container labels:

    perch.managed=true
    perch.project=<project>
    perch.service=<name>
    perch.source_hash=<hash>     # build identity (+ local content fingerprint)
    perch.config_hash=<hash>     # env / ports / security / route / ...

Containers are named  perch-<project>-<service>  and images are tagged
perch/<project>-<service>:<source_hash>.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from .backend import LiveService, RenderContext
from .manifest import Service


class DockerError(RuntimeError):
    pass


def _docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    if shutil.which("docker") is None:
        raise DockerError("docker CLI not found on PATH -- install Docker to use this backend")
    return subprocess.run(["docker", *args], text=True,
                          capture_output=capture, check=check)


class DockerBackend:
    label_managed = "perch.managed=true"

    def _cname(self, project: str, name: str) -> str:
        return f"perch-{project}-{name}"

    def _image(self, project: str, name: str, source_hash: str) -> str:
        return f"perch/{project}-{name}:{source_hash}"

    # ---- network --------------------------------------------------------
    def ensure_network(self, project: str) -> str:
        """Create the project's main bridge network and an `--internal` network
        (no route off-box) used for egress-restricted workloads (C8)."""
        from . import egress
        existing = _docker("network", "ls", "--format", "{{.Name}}").stdout.split()
        main = egress.main_network(project)
        internal = egress.internal_network(project)
        if main not in existing:
            _docker("network", "create", main)
        if internal not in existing:
            _docker("network", "create", "--internal", internal)
        return main

    def ensure_egress_proxy(self, project: str, service: str, allow_hosts: list[str]) -> None:
        """Run a per-workload default-deny forward proxy that only forwards the
        allowlisted hosts (C8), attached to the internal net (for the workload)
        and the main net (for the internet)."""
        from . import egress
        cname = egress.proxy_name(project, service)
        d = Path(tempfile.mkdtemp(prefix="perch-egress-"))
        (d / "tinyproxy.conf").write_text(egress.tinyproxy_config())
        (d / "filter").write_text(egress.tinyproxy_filter(allow_hosts))
        _docker("rm", "-f", cname, check=False)
        _docker("run", "-d", "--name", cname,
                "--network", egress.internal_network(project),
                "--label", self.label_managed,
                "--label", f"perch.project={project}",
                "--label", f"perch.service=egress-{service}",
                "--restart", "unless-stopped",
                # The proxy must not act as an IP router between its two nets;
                # enforce the Docker default explicitly so the only egress path
                # is the filtered HTTP(S) proxy itself.
                "--sysctl", "net.ipv4.ip_forward=0",
                "-v", f"{d / 'tinyproxy.conf'}:/etc/tinyproxy/tinyproxy.conf:ro",
                "-v", f"{d / 'filter'}:/etc/tinyproxy/filter:ro",
                "vimagick/tinyproxy", check=False, capture=False)
        _docker("network", "connect", egress.main_network(project), cname, check=False)

    def ensure_mcp_gateway(self, project: str, service: str, image: str,
                           config: dict, host_spool_dir: str) -> None:
        """Run a per-agent MCP mediating gateway (C9): our stdlib gateway code on a
        minimal python image, with the perch package mounted read-only and the
        policy/servers config + decision spool mounted in. On the internal net (so
        the agent reaches it) and the main net (so it can reach HTTP upstreams)."""
        import perch
        from . import egress, mediation
        cname = mediation.gateway_name(project, service)
        pkg = Path(perch.__file__).resolve().parent          # the perch/ package dir
        # Stable per-service config dir (not a fresh mkdtemp each run): the gateway
        # config carries resolved upstream URLs (possibly secrets), so write it 0600
        # and overwrite in place rather than leaking accumulating world-readable copies.
        cfg_dir = Path(host_spool_dir).parent.parent / "mcp-config" / service
        cfg_dir.mkdir(parents=True, exist_ok=True)
        cfg_path = cfg_dir / "gateway.json"
        fd = os.open(str(cfg_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(config))
        os.chmod(cfg_path, 0o600)             # belt-and-suspenders across umasks/Windows
        Path(host_spool_dir).mkdir(parents=True, exist_ok=True)
        _docker("rm", "-f", cname, check=False)
        _docker("pull", image, check=False, capture=False)
        _docker("run", "-d", "--name", cname,
                "--network", egress.internal_network(project),
                "--label", self.label_managed,
                "--label", f"perch.project={project}",
                "--label", f"perch.service=mcp-{service}",
                "--restart", "unless-stopped",
                # Hardened like every other workload, and never an IP router between
                # its two nets -- the only path off-box for the agent is this gateway.
                "--sysctl", "net.ipv4.ip_forward=0",
                "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                "--security-opt", "no-new-privileges:true",
                "-e", "PYTHONPATH=/perch-pkg", "-e", "PYTHONDONTWRITEBYTECODE=1",
                "-v", f"{pkg}:/perch-pkg/perch:ro",
                "-v", f"{cfg_path}:/etc/perch/gateway.json:ro",
                "-v", f"{host_spool_dir}:/var/perch/spool",
                image, "python", "-m", "perch.gateway", "/etc/perch/gateway.json",
                check=False, capture=False)
        _docker("network", "connect", egress.main_network(project), cname, check=False)

    # ---- introspection --------------------------------------------------
    def list_managed(self, project: str) -> list[LiveService]:
        out = _docker("ps", "-a", "--filter", f"label={self.label_managed}",
                      "--filter", f"label=perch.project={project}",
                      "--format", "{{.Names}}").stdout.split()
        result = []
        for cname in out:
            ls = self._inspect(cname)
            if ls:
                result.append(ls)
        return result

    def get(self, project: str, name: str) -> LiveService | None:
        return self._inspect(self._cname(project, name))

    def _inspect(self, cname: str) -> LiveService | None:
        r = _docker("inspect", cname, check=False)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout)[0]
        labels = data["Config"].get("Labels") or {}
        state = data.get("State", {})
        health = (state.get("Health") or {}).get("Status")
        return LiveService(
            name=labels.get("perch.service", cname),
            status=state.get("Status", "unknown"),
            source_hash=labels.get("perch.source_hash"),
            config_hash=labels.get("perch.config_hash"),
            image=data["Config"].get("Image"),
            health=health or "none",
        )

    # ---- build context fingerprint -------------------------------------
    def fingerprint(self, svc: Service) -> str:
        """Hash of a local build context so editing code triggers a rebuild.
        Git URLs and prebuilt images return '' (use --rebuild to force)."""
        if not svc.build:
            return ""
        ctx = svc.build.context
        if "://" in ctx or ctx.startswith("git@"):
            return ""
        root = Path(ctx)
        if not root.exists():
            return ""
        h = hashlib.sha256()
        for p in sorted(root.rglob("*")):
            if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts:
                st = p.stat()
                h.update(f"{p.relative_to(root)}:{st.st_size}:{int(st.st_mtime)}".encode())
        return h.hexdigest()[:16]

    # ---- converge (build + recreate) -----------------------------------
    def converge(self, svc: Service, ctx: RenderContext) -> None:
        cname = self._cname(ctx.project, svc.name)
        tmp: list[str] = []
        if ctx.spec is not None:                      # managed service: run catalog image
            image = ctx.spec.image
            _docker("pull", image, check=False, capture=False)
            _docker("rm", "-f", cname, check=False)
            try:
                _docker("run", "-d", *self._run_args(svc, ctx, cname, image, cleanup=tmp), capture=True)
            finally:
                _cleanup(tmp)
            self._attach_networks(cname, ctx)
            self._provision_managed(svc, ctx)
            return
        image = svc.image or self._build(svc, ctx)    # app/agent: build or prebuilt
        _docker("rm", "-f", cname, check=False)
        try:
            _docker("run", "-d", *self._run_args(svc, ctx, cname, image, cleanup=tmp), capture=True)
        finally:
            _cleanup(tmp)
        self._attach_networks(cname, ctx)

    def _attach_networks(self, cname: str, ctx: RenderContext) -> None:
        for net in ctx.extra_networks:            # C8: managed svcs on both nets
            _docker("network", "connect", net, cname, check=False)

    def attach_internal(self, project: str, name: str) -> None:
        """Idempotently put a managed service on the internal network (covers a
        container that pre-dates C8 and wasn't re-converged on upgrade)."""
        from . import egress
        _docker("network", "connect", egress.internal_network(project),
                self._cname(project, name), check=False)

    def exec(self, project: str, name: str, cmd: list[str]) -> int:
        return _docker("exec", self._cname(project, name), *cmd,
                       check=False, capture=False).returncode

    def dump_postgres(self, project: str, name: str, out_path: str) -> None:
        """Stream a gzipped pg_dump from the running container to a host file."""
        import gzip
        cname = self._cname(project, name)
        proc = subprocess.run(
            ["docker", "exec", cname, "pg_dump", "-U", "app", "-d", "app"],
            capture_output=True, check=True)
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(out_path, "wb") as f:
            f.write(proc.stdout)

    def restore_postgres(self, project: str, name: str, in_path: str) -> int:
        """Restore a gzipped dump into the running container."""
        import gzip
        cname = self._cname(project, name)
        with gzip.open(in_path, "rb") as f:
            sql = f.read()
        proc = subprocess.run(
            ["docker", "exec", "-i", cname, "psql", "-U", "app", "-d", "app"],
            input=sql, capture_output=True)
        return proc.returncode

    def _provision_managed(self, svc: Service, ctx: RenderContext) -> None:
        """Best-effort post-start setup: DB extensions, storage buckets."""
        import time
        spec = ctx.spec
        if spec is None:
            return
        cname = self._cname(ctx.project, svc.name)
        if svc.type == "postgres" and spec.init_sql:
            for _ in range(30):                       # wait for readiness
                if _docker("exec", cname, "pg_isready", "-U", "app",
                           check=False).returncode == 0:
                    break
                time.sleep(1)
            _docker("exec", cname, "psql", "-U", "app", "-d", "app",
                    "-c", spec.init_sql, check=False)
        if svc.type == "storage" and spec.buckets:
            user = dict(spec.env).get("MINIO_ROOT_USER", "")
            pw = dict(spec.env).get("MINIO_ROOT_PASSWORD", "")
            mc = ["mc", "alias", "set", "local", "http://127.0.0.1:9000", user, pw]
            for _ in range(30):
                if _docker("exec", cname, *mc, check=False).returncode == 0:
                    break
                time.sleep(1)
            for bucket in spec.buckets:
                _docker("exec", cname, "mc", "mb", "--ignore-existing",
                        f"local/{bucket}", check=False)

    def run_once(self, svc: Service, ctx: RenderContext) -> int:
        image = svc.image or self._build(svc, ctx)
        cname = f"{self._cname(ctx.project, svc.name)}-job"
        _docker("rm", "-f", cname, check=False)
        tmp: list[str] = []
        args = self._run_args(svc, ctx, cname, image, restart=False, cleanup=tmp)
        try:
            r = _docker("run", "--rm", *[a for a in args if not a.startswith("--restart")],
                        check=False, capture=False)
        finally:
            _cleanup(tmp)
        return r.returncode

    def _build(self, svc: Service, ctx: RenderContext) -> str:
        if not svc.build:
            raise DockerError(f"service '{svc.name}' has neither image nor build")
        image = self._image(ctx.project, svc.name, ctx.source_hash)
        args = ["build", "-t", image, "-f", svc.build.dockerfile]
        for k, v in svc.build.args.items():
            args += ["--build-arg", f"{k}={v}"]
        if svc.build.target:
            args += ["--target", svc.build.target]
        args.append(svc.build.context)
        _docker(*args, capture=False)
        return image

    def _run_args(self, svc: Service, ctx: RenderContext, cname: str,
                  image: str, restart: bool = True,
                  cleanup: list[str] | None = None) -> list[str]:
        spec = ctx.spec
        sec = spec.security if spec else svc.security
        args = [
            "--name", cname, "--network", ctx.network,
            "--label", self.label_managed,
            "--label", f"perch.project={ctx.project}",
            "--label", f"perch.service={svc.name}",
            "--label", f"perch.source_hash={ctx.source_hash}",
            "--label", f"perch.config_hash={ctx.config_hash}",
            "--security-opt", "no-new-privileges:true" if sec.get("no_new_privileges", True) else "no-new-privileges:false",
        ]
        for cap in sec.get("drop_caps", ["ALL"]):
            args += ["--cap-drop", cap]
        for cap in sec.get("add_caps", []):
            args += ["--cap-add", cap]
        if sec.get("user"):
            args += ["--user", str(sec["user"])]
        if sec.get("read_only_rootfs", True):
            args += ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]
        if svc.resources.get("memory"):
            args += ["--memory", str(svc.resources["memory"])]
        if svc.resources.get("cpus"):
            args += ["--cpus", str(svc.resources["cpus"])]
        if restart:
            args += ["--restart", svc.restart]
        # volumes: managed spec volumes + user volumes
        for vol in ((spec.volumes if spec else []) + svc.volumes):
            vname, _, mount = vol.partition(":")
            args += ["-v", f"perch-{ctx.project}-{svc.name}-{vname}:{mount}"]
        port = (spec.internal_port if spec else None) or svc.port
        if port:
            args += ["--label", f"perch.port={port}"]
        if svc.route.host:
            args += ["--label", f"perch.route_host={svc.route.host}"]
        # env: managed spec env (credentials) + bindings/user env, via 0600 env-file.
        # The host temp file is deleted right after `docker run` reads it (see
        # converge/run_once) so credentials/tickets don't linger on disk.
        env = (spec.env if spec else []) + ctx.env
        if env:
            envfile = _write_envfile(env)
            if cleanup is not None:
                cleanup.append(envfile)
            args += ["--env-file", envfile]
        # healthcheck: managed spec command, or an HTTP probe for apps
        health = spec.health_cmd if spec else None
        if health:
            args += ["--health-cmd", health, "--health-interval", "30s",
                     "--health-retries", "3", "--health-timeout", "5s"]
        elif svc.health_path and svc.port:
            test = f"wget -qO- http://127.0.0.1:{svc.port}{svc.health_path} || exit 1"
            args += ["--health-cmd", test, "--health-interval", "30s",
                     "--health-retries", "3", "--health-timeout", "5s"]
        args.append(image)
        cmd = (spec.command if spec else None) or svc.command
        if cmd:
            args += cmd
        return args

    # ---- ops ------------------------------------------------------------
    def restart(self, project: str, name: str) -> None:
        _docker("restart", self._cname(project, name))

    def remove(self, project: str, name: str) -> None:
        _docker("rm", "-f", self._cname(project, name), check=False)

    def logs(self, project: str, name: str, follow: bool = False) -> Iterable[str]:
        args = ["logs", self._cname(project, name)]
        if follow:
            args.insert(1, "-f")
        proc = subprocess.Popen(["docker", *args], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        assert proc.stdout
        for line in proc.stdout:
            yield line.rstrip("\n")


def _write_envfile(env: list[tuple[str, str]]) -> str:
    fd, path = tempfile.mkstemp(prefix="perch-env-")
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        for k, v in env:
            f.write(f"{k}={v}\n")
    return path


def _cleanup(paths: list[str]) -> None:
    """Remove temp env-files once `docker run` has consumed them (best effort)."""
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass
