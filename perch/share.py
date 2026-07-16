"""
LAN sharing helpers for `perch share` (Windows-first, but portable).

A `route.host` like web.localhost only resolves on the developer's own machine, so
teammates on the office network can never open it. `perch share <service>` publishes
the service through the existing Caddy proxy on a dedicated port and prints
http://<LAN-IP>:<port>, then verifies reachability with a real probe instead of
assuming the rule/port worked. Research grounding (Docker Desktop licensing, the
three silent Windows Firewall failure modes, WSL2 NAT) lives in
docs/RESEARCH_windows-intranet-sharing.md.

Design rule: never fire-and-forget. Every environment mutation is followed by a
probe, and failures name who can fix them (including "hand this rule spec to IT"
when Group Policy makes local firewall rules a no-op).
"""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

SHARE_BASE = 8100          # first share port; one stable port per shared service
SHARE_MAX = 8199

# Windows Firewall policy registry roots (set by GPO/MDM). When AllowLocalPolicyMerge
# is 0 for a profile, locally created rules are silently ignored -- creation succeeds,
# traffic stays blocked -- so we must detect it and route the user to IT instead.
_POLICY_PROFILES = ("DomainProfile", "StandardProfile")   # Standard = Private
_POLICY_ROOT = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"


def allocate_port(existing: dict, base: int = SHARE_BASE) -> int:
    """Pick the next free share port, skipping ports already allocated to other
    services, so each service keeps a stable URL across runs. Accepts both share
    state shapes (bare port, or {port, https} entries)."""
    used = {v.get("port") if isinstance(v, dict) else v for v in existing.values()}
    for port in range(base, SHARE_MAX + 1):
        if port not in used:
            return port
    raise ValueError(f"no free share ports left in {base}-{SHARE_MAX}")


def lan_ip() -> "str | None":
    """The host's primary non-loopback IPv4 address (what a teammate would dial).
    Uses a UDP connect to a TEST-NET address to select the outbound interface; no
    packet is actually sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None
    finally:
        s.close()


def probe(ip: str, port: int, timeout: float = 3.0) -> bool:
    """TCP-connect to the shared port on the NON-loopback address. This is the
    verify half of every mutation; loopback would lie (it bypasses the firewall)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def in_wsl() -> bool:
    """True when this process runs inside WSL (where a 'reachable' port still sits
    behind WSL's NAT unless the Windows host forwards it)."""
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except OSError:
        return False


def classify(reachable: bool, windows: bool, wsl: bool) -> "tuple[str, str]":
    """Map a probe outcome to (status, guidance). Pure, so the matrix is testable.
    The three failure shapes have different fixes, so they must not share a message."""
    if reachable:
        return ("REACHABLE",
                "verified from this machine's LAN address; the final check is a "
                "teammate's browser")
    if wsl:
        return ("BLOCKED (WSL NAT)",
                "this port lives inside WSL's NAT network; the Windows host is not "
                "forwarding it. Enable WSL mirrored networking (.wslconfig: "
                "networkingMode=mirrored) or add a portproxy: netsh interface "
                "portproxy add v4tov4 listenport=<port> connectaddress=<WSL-IP>")
    if windows:
        return ("BLOCKED (likely Windows Firewall)",
                "Windows blocks inbound connections by default. Run `perch share "
                "<service> --fix` from an elevated PowerShell to add a scoped "
                "allow rule and re-verify")
    return ("BLOCKED",
            "the port did not answer on the LAN address; check the proxy is "
            "running and no host firewall is filtering it")


def normalize_shares(raw: dict) -> dict:
    """State shape migration: v1 stored {service: port}; v2 stores
    {service: {port, https}}. Accept both forever -- state files outlive releases,
    and silently dropping a share would silently unpublish someone's app."""
    out: dict = {}
    for name, v in (raw or {}).items():
        if isinstance(v, dict):
            port = v.get("port")
            if isinstance(port, int):
                out[name] = {"port": port, "https": bool(v.get("https", False))}
        elif isinstance(v, int):
            out[name] = {"port": v, "https": False}
    return out


# ---- Tailscale Serve (stable name + trusted TLS over the tailnet) ---------

def tailscale_path() -> "str | None":
    import shutil
    return shutil.which("tailscale")


def _dns_from_status(status_json: str) -> "str | None":
    """This machine's tailnet DNS name from `tailscale status --json`. Pure parse,
    injectable output, so the extraction is offline-testable."""
    import json
    try:
        name = (json.loads(status_json).get("Self") or {}).get("DNSName") or ""
    except (ValueError, AttributeError):
        return None
    return name.rstrip(".") or None


def tailscale_dns_name() -> "str | None":
    exe = tailscale_path()
    if not exe:
        return None
    r = subprocess.run([exe, "status", "--json"], capture_output=True, text=True)
    return _dns_from_status(r.stdout) if r.returncode == 0 else None


def tailscale_serve(port: int) -> "tuple[bool, str]":
    """Point Tailscale Serve at the local share port: teammates on the tailnet get
    https://<machine>.<tailnet>.ts.net with an automatically provisioned, publicly
    trusted certificate -- no firewall rule, no cert distribution. Returns
    (ok, detail) rather than raising so the CLI can report the failure verbatim."""
    exe = tailscale_path()
    if not exe:
        return False, "tailscale is not on PATH"
    r = subprocess.run([exe, "serve", "--bg", str(port)],
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stdout or r.stderr).strip()


def tailscale_hint(available: bool) -> "str | None":
    """One-line nudge shown when a LAN share is blocked and Tailscale is installed:
    Serve needs no firewall change, so it is often the faster path on a locked-down
    corporate machine. Teammates must be on the tailnet (that is the trade)."""
    if not available:
        return None
    return ("tailscale detected: `perch share <service> --tailscale` shares over "
            "your tailnet instead (trusted HTTPS, no firewall changes; teammates "
            "must be on the tailnet)")


# ---- Windows Firewall (US3) ----------------------------------------------

def rule_name(port: int) -> str:
    return f"Perch share {port}"


def firewall_rule_spec(port: int) -> str:
    """The exact rule, as one PowerShell command. Used three ways: executed by
    --fix, shown to the user before mutating, and handed to IT verbatim when local
    rules cannot take effect. Scoped to Domain/Private profiles only -- never Public,
    so the app is not exposed on untrusted networks (coffee-shop Wi-Fi)."""
    return (f'New-NetFirewallRule -DisplayName "{rule_name(port)}" '
            f"-Direction Inbound -Action Allow -Protocol TCP "
            f"-LocalPort {port} -Profile Domain,Private")


def is_admin() -> bool:
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _reg_read(profile: str, name: str):
    """Read one Windows Firewall policy value from the GPO policy store; None when
    the key/value doesn't exist (no policy set)."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{_POLICY_ROOT}\\{profile}") as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def policy_merge_disabled(read=_reg_read) -> bool:
    """True when Group Policy disables local firewall rule merge on the Domain or
    Private profile: our rule would be created 'successfully' and then ignored.
    `read` is injectable so the logic is testable off-Windows."""
    for profile in _POLICY_PROFILES:
        if read(profile, "AllowLocalPolicyMerge") == 0:
            return True
    return False


def _powershell(command: str) -> "subprocess.CompletedProcess":
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True)


def add_firewall_rule(port: int) -> bool:
    return _powershell(firewall_rule_spec(port)).returncode == 0


def remove_firewall_rule(port: int) -> bool:
    return _powershell(
        f'Remove-NetFirewallRule -DisplayName "{rule_name(port)}"').returncode == 0
