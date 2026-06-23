"""
A minimal demo agent for the secure-agent example -- replace with your own code.

It does just enough to SHOW the secure-by-default posture working at runtime,
using only the Python standard library (no pip install, nothing to audit):

  * prints its per-run identity subject and confirms a brokered DB credential was
    injected (without printing the secret itself),
  * talks to its MCP mediation gateway the way a real MCP client would -- a tool
    that is NOT on the allowlist comes back as a JSON-RPC error, proving mediation,
  * then idles, so `perch status` / `perch logs assistant` show it running.

Everything it needs is injected by Perch as environment; it holds no static secret
and (with `egress:` set) has no outbound path except the gateway.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _say(msg: str) -> None:
    print(f"[assistant] {msg}", flush=True)


def _gateway_call(base: str, token: str | None, body: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"{}")


def main() -> int:
    _say(f"identity subject: {os.environ.get('PERCH_IDENTITY_SUBJECT', '<none>')}")

    # A brokered, per-run DB credential is injected (PERCH_CREDENTIAL_* or a
    # connection URL) -- never a static password baked into the image.
    cred = next((k for k in os.environ
                 if k.startswith("PERCH_CREDENTIAL_") or k.endswith("DATABASE_URL")), None)
    _say(f"brokered DB credential present: {bool(cred)}" + (f" (in ${cred})" if cred else ""))

    gateway = os.environ.get("PERCH_MCP_GATEWAY")
    token = os.environ.get("PERCH_MCP_TOKEN")
    if gateway:
        base = gateway.rstrip("/") + "/"
        try:
            resp = _gateway_call(base, token, {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "github.delete_repo"},   # deliberately NOT allow-listed
            })
            if "error" in resp:
                _say(f"gateway DENIED github.delete_repo -> {resp['error']['message']} "
                     f"(mediation working)")
            else:
                _say(f"unexpected: gateway allowed a non-allow-listed tool: {resp}")
        except urllib.error.HTTPError as e:
            _say(f"gateway returned HTTP {e.code} (e.g. 401 if the token is missing)")
        except Exception as e:                              # noqa: BLE001 -- demo: report, don't crash
            _say(f"could not reach gateway yet: {e!r}")
    else:
        _say("no MCP gateway configured (no `mcp:` block)")

    _say("startup checks done; idling. Replace agent.py with your real agent.")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
