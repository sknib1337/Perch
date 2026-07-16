"""
Windows integration check for `perch share` plumbing (US3): runs on a windows-latest
CI runner (admin), exercising the pieces that can only be proven on real Windows:

  * lan_ip() finds a non-loopback address and probe() reaches a real listener on it
    (and correctly fails on a closed port),
  * add_firewall_rule / remove_firewall_rule round-trip against the real firewall
    (verified via Get-NetFirewallRule, not just exit codes),
  * policy_merge_disabled() reads the real GPO policy store without crashing.

Honest scope note: a self-probe cannot prove a SECOND machine can connect (loopback
paths can bypass filtering), which is why `perch share` wording and the sprint's
acceptance criteria keep the two-device check as a manual demo step. This check
verifies the mechanics: rule creation, verification, detection, and cleanup.

Run:  python tests/windows_share_check.py   (skips cleanly on non-Windows)
"""
import os
import socket
import subprocess
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


def _rule_exists(name: str) -> bool:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        f'Get-NetFirewallRule -DisplayName "{name}"'],
                       capture_output=True, text=True)
    return r.returncode == 0 and name in r.stdout


def run() -> int:
    if os.name != "nt":
        print("SKIP: Windows-only check")
        return 0
    from perch import share

    ip = share.lan_ip()
    check("lan_ip returns a non-loopback address", bool(ip), f"got {ip!r}")
    if not ip:
        return 2

    # a real listener on the LAN address is REACHABLE; a closed port is not
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    check("probe reaches a live listener on the LAN address", share.probe(ip, port))
    srv.close()
    check("probe fails closed on a dead port", not share.probe(ip, port, timeout=1.0))

    check("policy_merge_disabled reads the real policy store",
          share.policy_merge_disabled() in (True, False))
    admin = share.is_admin()
    print(f"  (running as admin: {admin})")

    if admin:
        fw_port = 18143                      # arbitrary high port for the round-trip
        name = share.rule_name(fw_port)
        try:
            check("firewall rule created", share.add_firewall_rule(fw_port))
            check("firewall rule visible in Get-NetFirewallRule", _rule_exists(name))
        finally:
            removed = share.remove_firewall_rule(fw_port)
            check("firewall rule removed (cleanup)", removed and not _rule_exists(name))
    else:
        print("  (skipping firewall rule round-trip: not elevated)")

    print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
    if FAIL:
        print("FAILED:", ", ".join(FAIL))
    return 0 if not FAIL else 2


if __name__ == "__main__":
    raise SystemExit(run())
