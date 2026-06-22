"""
C9 -- MCP message model + mediation decision (pure, offline-tested).

The gateway (`perch/gateway.py`) speaks MCP, which is JSON-RPC 2.0 over HTTP or
stdio. This module is the transport-agnostic decision core: given one parsed
JSON-RPC message and a `MediationPolicy`, decide whether to forward it, deny it, or
forward-and-filter the response. It is deliberately pure -- no sockets, no upstream
routing (the gateway handles that) -- so every method can be exhaustively unit-tested.

Authorization target per method:
  - tools/call            -> the tool name (params.name), a `server.tool`
  - resources/read,
    resources/subscribe   -> the resource URI (params.uri)
  - prompts/get           -> the prompt name (params.name), a `server.prompt`
  - tools/list,
    resources/list,
    prompts/list          -> allowed, but the response is filtered to the allowlist
  - sampling/createMessage-> policy.sampling (a server->agent escalation channel)
  - completion/complete   -> policy.completion
  - initialize, ping,
    notifications/*, etc.  -> handshake/control, passed through
  - anything else          -> denied, closed

Everything fails closed: a non-dict message, a non-string method, missing params,
or an unknown method is denied rather than forwarded.
"""

from __future__ import annotations

from dataclasses import dataclass

from .mediation import MediationDecision, MediationPolicy, _clean

JSONRPC_VERSION = "2.0"

# The gateway enforces these on the raw wire bytes before parsing; exported here so
# transport and policy share one definition.
MAX_MESSAGE_BYTES = 1 << 20        # 1 MiB per JSON-RPC message
MAX_BATCH_ELEMENTS = 100           # cap a JSON-RPC batch so it can't fan out unbounded work
DENIED_CODE = -32001               # JSON-RPC server-error range: "not authorized"
PARSE_ERROR_CODE = -32700          # JSON-RPC: invalid JSON

# Methods that carry no authorization target -- handshake/lifecycle/control. Passed
# through so a session can establish; the security-relevant calls are gated below.
_PASSTHROUGH = {
    "initialize", "initialized", "ping",
    "logging/setLevel", "roots/list", "completion/list",
}

# list methods: allowed, but their *response* is filtered to the allowlist (so the
# model never even sees a disallowed capability). Maps method -> capability.
_LIST_FILTER = {
    "tools/list": "tools",
    "resources/list": "resources",
    "prompts/list": "prompts",
}


@dataclass
class Mediation:
    """One message's verdict. `filter` names the capability whose list response the
    gateway must trim ('tools'|'resources'|'prompts'); None means no filtering."""
    method: str
    target: str
    allowed: bool
    reason: str
    filter: "str | None" = None
    rpc_id: "object | None" = None
    is_request: bool = False


def _params(message: dict) -> dict:
    p = message.get("params")
    return p if isinstance(p, dict) else {}


def mediate(message, policy: MediationPolicy) -> Mediation:
    """Authorize a single JSON-RPC message against the policy. Fails closed."""
    if not isinstance(message, dict):
        return Mediation("", "", False, "malformed message (not a JSON-RPC object)")
    method = message.get("method")
    rpc_id = message.get("id")
    is_request = "id" in message
    if not isinstance(method, str) or not method:
        return Mediation("", "", False, "missing or invalid method",
                         rpc_id=rpc_id, is_request=is_request)

    def verdict(target: str, decision: MediationDecision, filt=None) -> Mediation:
        return Mediation(method, target, decision.allowed, decision.reason,
                         filter=filt, rpc_id=rpc_id, is_request=is_request)

    def passed(reason: str, filt=None) -> Mediation:
        return Mediation(method, "", True, reason, filter=filt,
                         rpc_id=rpc_id, is_request=is_request)

    def denied(reason: str) -> Mediation:
        return Mediation(method, "", False, reason, rpc_id=rpc_id, is_request=is_request)

    params = _params(message)

    if method in _PASSTHROUGH or method.startswith("notifications/"):
        return passed("passthrough (handshake/control)")
    if method in _LIST_FILTER:
        return passed("list -- response filtered to allowlist", filt=_LIST_FILTER[method])
    if method == "tools/call":
        clean = _clean(params.get("name"))          # canonical name used everywhere downstream
        if clean is None:
            return denied("invalid tool name")
        return verdict(clean, policy.authorize_tool(clean))
    if method in ("resources/read", "resources/subscribe", "resources/unsubscribe"):
        clean = _clean(params.get("uri"))
        if clean is None:
            return denied("invalid resource uri")
        return verdict(clean, policy.authorize_resource(clean))
    if method == "resources/templates/list":
        # Templates only advertise shapes; the actual read is gated by resources/read.
        return passed("passthrough (template listing; reads still gated)")
    if method == "prompts/get":
        clean = _clean(params.get("name"))
        if clean is None:
            return denied("invalid prompt name")
        return verdict(clean, policy.authorize_prompt(clean))
    if method == "sampling/createMessage":
        ok = policy.sampling
        return Mediation(method, "", ok,
                         "sampling allowed" if ok else "sampling denied (default deny)",
                         rpc_id=rpc_id, is_request=is_request)
    if method == "completion/complete":
        ok = policy.completion
        return Mediation(method, "", ok,
                         "completion allowed" if ok else "completion denied (default deny)",
                         rpc_id=rpc_id, is_request=is_request)
    return denied(f"unknown method {method!r} (default deny)")


def mediate_payload(payload, policy: MediationPolicy) -> "list[tuple[object, Mediation]]":
    """Mediate a single message or a JSON-RPC batch (array). Returns
    (message, Mediation) per element, preserving order. A non-object/array payload
    is a single closed deny."""
    if isinstance(payload, list):
        return [(m, mediate(m, policy)) for m in payload]
    return [(payload, mediate(payload, policy))]


def jsonrpc_error(rpc_id, message: str, code: int = DENIED_CODE) -> dict:
    """A spec-compliant JSON-RPC error object the gateway returns to the agent."""
    return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id,
            "error": {"code": code, "message": message}}


def filter_list_result(capability: str, result, policy: MediationPolicy):
    """Trim a *_/list result to the allowlist so disallowed capabilities are never
    advertised. `result` is the JSON-RPC `result` object; unknown shapes pass
    through untouched (the per-call gate is still the real control)."""
    if not isinstance(result, dict):
        return result
    key = {"tools": "tools", "resources": "resources", "prompts": "prompts"}[capability]
    items = result.get(key)
    if not isinstance(items, list):
        return result
    if capability == "tools":
        keep = lambda it: isinstance(it, dict) and policy.authorized_tool(it.get("name", ""))
    elif capability == "prompts":
        keep = lambda it: isinstance(it, dict) and policy.authorized_prompt(it.get("name", ""))
    else:  # resources
        keep = lambda it: isinstance(it, dict) and policy.authorized_resource(it.get("uri", ""))
    return {**result, key: [it for it in items if keep(it)]}
