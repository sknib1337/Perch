# Securing an agent end-to-end

This example runs one AI agent under the full opt-in posture: a per-run least-privilege
database identity (C1/C2/C5/C6), default-deny egress (C8), mediated tool calls (C9), and
optional image pinning (C12). Each block in [`perch.yaml`](perch.yaml) is independent —
remove any and the agent still runs.

## 1. Deploy

```bash
export ANTHROPIC_API_KEY=...        # whatever your agent needs at runtime
perch -f examples/secure-agent/perch.yaml up
```

Perch starts Postgres, mints the agent a **per-run, read-only** database credential
(not a static password), puts the agent on an internal network with a default-deny
egress proxy that only allows `api.anthropic.com`, and launches the agent's **MCP
mediation gateway** sidecar.

## 2. Point the agent's MCP client at its gateway

The agent must talk to its gateway instead of directly to MCP servers — that's what
makes every tool call mediated. Generate the client config:

```bash
perch -f examples/secure-agent/perch.yaml mcp-config assistant
```

```json
{
  "mcpServers": {
    "perch-gateway": {
      "type": "http",
      "url": "http://perch-secure-agent-demo-mcp-assistant:8900/",
      "headers": { "Authorization": "Bearer <per-agent token>" }
    }
  }
}
```

Drop that into your agent's MCP client config (the `mcpServers` schema used by Claude
Desktop / Claude Code and compatible clients). The agent now sees one MCP server — the
gateway — which multiplexes to the real upstreams in `mcp.servers`, but only forwards
the allow-listed tools. Because egress is locked down, the gateway is the agent's only
outbound path, so it cannot reach an upstream directly.

The `Authorization` bearer (C1) is a per-agent token sealed in `.perch/state.json`; the
gateway requires it on every request, so a co-resident container can't use the gateway.
For an MCP client that can't send a header, set `mcp: { auth: false }` (and rely on the
network boundary instead).

## 3. What's enforced

| You declared | What happens at runtime |
|---|---|
| `identity: { scopes: { db: read } }` | A fresh Postgres role per run, `SELECT`-only, expiring on `ttl`. No static `DATABASE_URL` password. |
| `egress: { allow: [api.anthropic.com] }` | Internal network + filtering proxy; any other host is refused. |
| `mcp: { allow: { tools: [...] } }` | Gateway authorizes every call; non-allow-listed tools get a JSON-RPC error and never reach the upstream. `*/list` is filtered so the model never even sees them. |
| repeated denied tool calls | Folded into the tamper-evident audit log; the `Detector` quarantines the subject and the gateway then denies it outright. |

## 4. Verify it's actually mediating

A repeatable, Docker-free end-to-end check of the gateway (real sockets + a real
subprocess, exercising the same `perch.gateway` code the container runs):

```bash
python tests/e2e_gateway.py
```

See [THREAT_MODEL.md](../../THREAT_MODEL.md) for the controls (C1–C12) and their
documented residuals.
