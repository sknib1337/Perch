"""
C9 -- MCP & tool-call mediation.

An agent decides which tools to call from model output, so "trust the agent to
only call safe tools" is not a control. Perch's answer is to be the broker-of-
record: an agent declares the tools/MCP methods it may use, and a mediating
gateway authorizes every call against that default-deny allowlist and records the
decision. Combined with C8 egress (the agent's only outbound path is the gateway),
the agent cannot route around it.

This module is the pure policy + audit core:
  - `ToolPolicy`      -- default-deny allowlist of `server.tool` glob patterns.
  - `MediationPolicy` -- full-coverage policy (tools, resources, prompts, sampling,
                         completion) the gateway authorizes every MCP message against.
  - `MediationDecision` / `audit_record` -- the per-call verdict and its log entry.

The mediating gateway process that calls this per request lives in `perch/gateway.py`
(a per-agent sidecar the agent's MCP client points at). Paired with C8 egress -- the
agent's only outbound path is the gateway -- the agent cannot route around it. Each
decision is appended to a spool the reconciler folds into C10/C11's tamper-evident
audit + quarantine loop.

Manifest (all keys optional; a bare `allow: [..]` list is read as tool patterns):
    mcp:
      servers:
        github: https://mcp.example.com/github        # HTTP upstream
        fs: { command: ["python","-m","mcp_server_fs","/data"], transport: stdio }
      allow:
        tools:     ["github.*", "fs.read_*"]          # server.tool globs
        resources: ["fs://**"]                        # resource-URI path globs
        prompts:   ["github.*"]                        # server.prompt globs
      sampling: false        # server->agent sampling, default deny
      completion: false
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


def _compile_path(pattern: str) -> "re.Pattern":
    """Translate a resource-URI glob: `*` matches within a path segment (never
    crosses `/`), `**` matches across segments, and every other character --
    including `.` -- is literal. So `fs://**` allows all `fs` resources while
    `fs://docs/*` can't reach into a subdirectory. A bare `*` is allow-all."""
    if pattern == "*":
        return re.compile(r".*", re.DOTALL)
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*"); i += 2
            else:
                out.append("[^/]*"); i += 1
        else:
            out.append(re.escape(pattern[i])); i += 1
    return re.compile("".join(out), re.DOTALL)


def _clean(name) -> "str | None":
    """Validate an authorization target without mutating it: reject non-strings,
    empty, and any name containing whitespace or a control character. We do NOT
    silently strip -- `str.strip()` removes Unicode spaces (NBSP, U+2000..) that the
    `ord < 0x20` check misses, which would let `fs.read\\xa0` match the rule `fs.read`
    while a DIFFERENT (un-stripped) name is forwarded/audited. Tool/resource/prompt
    names never contain whitespace, so any is a reason to deny, closed."""
    if not isinstance(name, str) or not name:
        return None
    if any(c.isspace() or ord(c) < 0x20 for c in name):
        return None
    return name


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
        # Validate without mutating (see _clean): a name with whitespace/control
        # chars is denied outright rather than silently normalized, so the matched
        # name is exactly the name that gets forwarded and audited.
        clean = _clean(tool)
        if clean is None:
            return MediationDecision(tool if isinstance(tool, str) else str(tool),
                                     False, "invalid tool name")
        tool = clean
        for pat, rx in self._compiled:
            if rx.fullmatch(tool):
                return MediationDecision(tool, True, f"allowed by {pat!r}")
        return MediationDecision(tool, False, "no allow rule matched (default deny)")

    def authorized(self, tool: str) -> bool:
        return self.authorize(tool).allowed


class MediationPolicy:
    """Full-coverage, default-deny policy the gateway applies to every MCP message:
    tool calls, resource reads, and prompt fetches each have their own allowlist,
    and server->agent `sampling`/`completion` are off unless explicitly enabled.

    Built from the manifest `mcp:` block. A bare `allow: [..]` list (the original
    shape) is read as tool patterns so existing manifests keep working unchanged."""

    def __init__(self, *, tools=None, resources=None, prompts=None,
                 sampling: bool = False, completion: bool = False):
        self.tools = ToolPolicy(tools)                  # reuse server.tool glob engine
        self.prompts = ToolPolicy(prompts)              # server.prompt -- same shape
        self.resource_patterns = [str(p).strip() for p in (resources or []) if str(p).strip()]
        self._resources = [(p, _compile_path(p)) for p in self.resource_patterns]
        self.sampling = bool(sampling)
        self.completion = bool(completion)

    # ---- per-capability authorization (each fails closed) ---------------
    def authorize_tool(self, name: str) -> MediationDecision:
        return self.tools.authorize(name)

    def authorize_prompt(self, name: str) -> MediationDecision:
        return self.prompts.authorize(name)

    def authorize_resource(self, uri: str) -> MediationDecision:
        clean = _clean(uri)
        if clean is None:
            return MediationDecision(str(uri), False, "invalid resource uri")
        for pat, rx in self._resources:
            if rx.fullmatch(clean):
                return MediationDecision(clean, True, f"allowed by {pat!r}")
        return MediationDecision(clean, False, "no allow rule matched (default deny)")

    # convenience predicates used by response filtering in the gateway
    def authorized_tool(self, name: str) -> bool:
        return self.tools.authorized(name)

    def authorized_resource(self, uri: str) -> bool:
        return self.authorize_resource(uri).allowed

    def authorized_prompt(self, name: str) -> bool:
        return self.prompts.authorized(name)

    # back-compat: a bare tool check (older callers used ToolPolicy directly)
    def authorize(self, tool: str) -> MediationDecision:
        return self.authorize_tool(tool)

    def authorized(self, tool: str) -> bool:
        return self.tools.authorized(tool)

    # ---- (de)serialization: mounted into the gateway container ----------
    @staticmethod
    def from_manifest(mcp: dict) -> "MediationPolicy":
        mcp = mcp or {}
        allow = mcp.get("allow")
        if isinstance(allow, dict):
            tools = allow.get("tools", [])
            resources = allow.get("resources", [])
            prompts = allow.get("prompts", [])
        elif isinstance(allow, list):                   # original shape -> tools only
            tools, resources, prompts = allow, [], []
        else:
            tools = resources = prompts = []
        return MediationPolicy(tools=tools, resources=resources, prompts=prompts,
                               sampling=mcp.get("sampling", False),
                               completion=mcp.get("completion", False))

    def to_config(self) -> dict:
        return {"tools": list(self.tools.allow), "prompts": list(self.prompts.allow),
                "resources": list(self.resource_patterns),
                "sampling": self.sampling, "completion": self.completion}

    @staticmethod
    def from_config(d: dict) -> "MediationPolicy":
        d = d or {}
        return MediationPolicy(tools=d.get("tools"), resources=d.get("resources"),
                               prompts=d.get("prompts"), sampling=d.get("sampling", False),
                               completion=d.get("completion", False))


def audit_record(subject: str, decision: MediationDecision, at: int) -> dict:
    """A structured, loggable record of one mediation decision (the broker-of-
    record entry). `at` is a caller-supplied timestamp (kept injectable so the
    record is deterministic and so it can be chained into the C10 tamper-evident
    log without this module depending on the clock)."""
    return {
        "subject": subject, "tool": decision.tool,
        "allowed": decision.allowed, "reason": decision.reason, "at": int(at),
    }
