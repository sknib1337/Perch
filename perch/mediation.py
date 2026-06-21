"""
C9 -- MCP & tool-call mediation.

An agent decides which tools to call from model output, so "trust the agent to
only call safe tools" is not a control. Perch's answer is to be the broker-of-
record: an agent declares the tools/MCP methods it may use, and a mediating
gateway authorizes every call against that default-deny allowlist and records the
decision. Combined with C8 egress (the agent's only outbound path is the gateway),
the agent cannot route around it.

This module is the pure policy + audit core, which is implemented and tested:
  - `ToolPolicy`  -- default-deny allowlist of `server.tool` glob patterns.
  - `MediationDecision` / `audit_record` -- the per-call verdict and its log entry.

The mediating gateway process (an MCP proxy the agent's client points at) is the
enforcement point that calls `ToolPolicy.authorize` per request; it is NOT yet
shipped. Enforcement also requires C8 egress to be configured so the agent's only
outbound path is the gateway -- until both land, the policy here is declarative
intent, not a runtime control. The audit log is a natural consumer of C10's
tamper-evident log.

Manifest:
    mcp:
      allow:
        - "github.*"           # any tool on the github server
        - "fs.read_*"          # only read_* tools on the fs server
        - "search.query"       # one exact tool
"""

from __future__ import annotations

import re
from dataclasses import dataclass

GATEWAY_PORT = 8900


def _compile(pattern: str) -> "re.Pattern":
    """Translate a tool-name glob to a regex where `*` matches within a single
    `server.tool` segment only (never across a dot), so an allow rule can't
    over-match into a different segment. A bare `*` is the explicit allow-all.
    Every other character (including `?`, `[`, `]`) is matched literally, so a
    pattern's metacharacters can't silently broaden authorization."""
    if pattern == "*":
        return re.compile(r".*", re.DOTALL)
    rx = "".join("[^.]*" if ch == "*" else re.escape(ch) for ch in pattern)
    return re.compile(rx)


def gateway_name(project: str, service: str) -> str:
    return f"perch-{project}-mcp-{service}"


def gateway_env(project: str, service: str) -> dict:
    """Point an agent's MCP client at its mediating gateway."""
    return {"PERCH_MCP_GATEWAY": f"http://{gateway_name(project, service)}:{GATEWAY_PORT}"}


@dataclass
class MediationDecision:
    tool: str
    allowed: bool
    reason: str


class ToolPolicy:
    """Default-deny allowlist for an agent's tool/MCP calls. A tool is named
    `server.tool`; patterns are globs over that name (`github.*`, `fs.read_*`,
    `*`). With no patterns, everything is denied."""

    def __init__(self, allow=None):
        self.allow = [str(p).strip() for p in (allow or []) if str(p).strip()]
        self._compiled = [(p, _compile(p)) for p in self.allow]

    def authorize(self, tool: str) -> MediationDecision:
        if not isinstance(tool, str):
            return MediationDecision(str(tool), False, "invalid tool name")
        tool = tool.strip()
        # Reject empty and any control character (newline/null/...) before matching
        # so a crafted name can't slip a wildcard past the allowlist.
        if not tool or any(ord(c) < 0x20 for c in tool):
            return MediationDecision(tool, False, "invalid tool name")
        for pat, rx in self._compiled:
            if rx.fullmatch(tool):
                return MediationDecision(tool, True, f"allowed by {pat!r}")
        return MediationDecision(tool, False, "no allow rule matched (default deny)")

    def authorized(self, tool: str) -> bool:
        return self.authorize(tool).allowed


def audit_record(subject: str, decision: MediationDecision, at: int) -> dict:
    """A structured, loggable record of one mediation decision (the broker-of-
    record entry). `at` is a caller-supplied timestamp (kept injectable so the
    record is deterministic and so it can be chained into the C10 tamper-evident
    log without this module depending on the clock)."""
    return {
        "subject": subject, "tool": decision.tool,
        "allowed": decision.allowed, "reason": decision.reason, "at": int(at),
    }
