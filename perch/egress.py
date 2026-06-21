"""
C8 -- egress control / network segmentation.

A compromised or prompt-injected agent's first move is usually to phone home or
exfiltrate. By default Docker gives every container unrestricted outbound
internet; this lets a workload declare a tighter posture:

    egress: all                      # default -- today's behavior (full internet)
    egress: deny                     # no outbound internet at all
    egress: { allow: [api.x.com] }   # only these hosts (and subdomains)

Mechanism (single host, no NET_ADMIN needed in the workload):
  - `all`   -> the workload runs on the project's normal bridge network.
  - `deny`  -> it runs on an `--internal` network (Docker gives it no IP route
               off-box); it can still reach managed services, which are attached to
               both nets.
  - `allow` -> internal network + HTTP(S)_PROXY pointed at a default-deny egress
               proxy that only forwards the allowlisted hosts. Anything not on the
               list is refused at the proxy, and there's no direct route around it.

Residuals (see THREAT_MODEL C8): `deny`/`allow` block the IP data plane, but
Docker's embedded DNS resolver still forwards queries upstream, so DNS remains a
low-bandwidth covert channel; and a workload handed an *admin* credential for a
managed service that can itself make outbound calls (e.g. MinIO webhooks, Zitadel
actions) could relay through it -- prefer identity-scoped, non-admin creds (C5/C6)
for egress-restricted workloads.

This module is pure (policy + config generation + network naming); the reconciler
decides the network/proxy env and the backend wires the topology and runs the proxy.

Seam for later phases: the egress proxy is also the natural choke point for C9
(mediating/logging an agent's outbound tool/MCP calls).
"""

from __future__ import annotations

import re

EGRESS_PORT = 8888


def policy(egress) -> "tuple[str, list]":
    """Normalize a `Service.egress` value to (mode, allow_hosts). Fail closed: an
    explicit-but-unrecognized value denies rather than silently allowing."""
    if egress is None or egress == "all":
        return ("all", [])
    if egress in ("deny", "none", False):
        return ("deny", [])
    if isinstance(egress, dict) and egress.get("allow"):
        return ("allow", [str(h).strip() for h in egress["allow"] if str(h).strip()])
    return ("deny", [])


def main_network(project: str) -> str:
    return f"perch-{project}"


def internal_network(project: str) -> str:
    return f"perch-{project}-internal"


def network_for(project: str, egress) -> str:
    """The network a workload runs on: the normal bridge for full egress, the
    internal (no-internet) network for deny/allow."""
    mode, _ = policy(egress)
    return main_network(project) if mode == "all" else internal_network(project)


def proxy_name(project: str, service: str) -> str:
    # One proxy per allow-workload, so each workload's allowlist is enforced on
    # its own and a shared union can't widen anyone's egress.
    return f"perch-{project}-egress-{service}"


def proxy_env(project: str, service: str, no_proxy_hosts=()) -> dict:
    """HTTP(S)_PROXY env routing a workload's outbound traffic through ITS egress
    proxy. `no_proxy_hosts` (managed-service hosts, localhost) bypass it so
    intra-project traffic isn't proxied."""
    url = f"http://{proxy_name(project, service)}:{EGRESS_PORT}"
    no_proxy = ",".join(["localhost", "127.0.0.1", *no_proxy_hosts])
    return {"HTTP_PROXY": url, "HTTPS_PROXY": url, "http_proxy": url, "https_proxy": url,
            "NO_PROXY": no_proxy, "no_proxy": no_proxy}


def _host_pattern(host: str) -> str:
    # Allow the exact host and its subdomains: (^|\.)example\.com$
    return r"(^|\.)" + re.escape(host) + r"$"


def tinyproxy_filter(allow_hosts) -> str:
    """The allowlist file: one anchored host pattern per line. With
    FilterDefaultDeny, only these hosts (and subdomains) are forwarded."""
    return "".join(_host_pattern(h) + "\n" for h in allow_hosts)


def tinyproxy_config() -> str:
    """A default-deny forward proxy: everything is refused unless it matches the
    allowlist filter file."""
    return (
        f"Port {EGRESS_PORT}\n"
        "Listen 0.0.0.0\n"
        "Timeout 600\n"
        "FilterDefaultDeny Yes\n"
        'Filter "/etc/tinyproxy/filter"\n'
        "FilterExtended On\n"
        "FilterURLs Off\n"            # match on host only -- the anchored patterns assume it
        "FilterCaseSensitive Off\n"
    )
