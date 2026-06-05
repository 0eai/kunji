# kunji MCP bridge

Let an AI runtime (Claude Code / Claude Desktop) **act for you at an app** using a
user-authorized, scoped, expiring **capability** — never your kunji keys. This is the
Phase-4 bridge over the agentic-delegation protocol (`../../docs/agentic-delegation.md`).

The bridge holds only the **agent's own** keypair (generated locally, never transmitted)
plus a capability you mint in your wallet. The kunji master key and per-app keys never
touch this machine.

## How it works

```
 you, in the kunji wallet                 the AI runtime + this MCP server
 ────────────────────────                 ────────────────────────────────
                                  kunji_authorize(audience, scope)
                                     → prints a request { kunjiCap, audience, scope, agentPub }
 Security → "Authorize an agent"
   scan/paste the request → Approve
   → copy the capability  ───────►  kunji_set_capability(capability)
                                     (validated: holder-of-key + not expired)
                                  kunji_login(baseUrl)
                                     → creates a session, signs its challenge with the
                                       agent key, POSTs /kunji/agent → { sub, scope, status }
```

Every sensitive step is gated: nothing works until **you** approve the capability in the
wallet, and the capability is bound to this agent's key (a stolen capability is useless),
scoped, and time-boxed. Revoke by adding its `jti` to the RP's `revokedCapabilities`.

## Tools

| Tool | What it does |
|---|---|
| `kunji_authorize` | `{ audience, scope? }` → the request for you to approve in the wallet |
| `kunji_set_capability` | `{ capability }` → store the wallet-issued capability (validated) |
| `kunji_login` | `{ baseUrl }` → sign in at the RP as the authorized agent → `{ sub, scope, status }` |
| `kunji_status` | the agent's public key + the loaded capability (audience/scope/expiry) |

## Setup

```bash
cd examples/kunji-mcp
npm install
```

Register with **Claude Code**:

```bash
claude mcp add kunji -- node /abs/path/to/examples/kunji-mcp/server.js
claude mcp list   # expect: kunji ✓ Connected
```

Or **Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kunji": { "command": "node", "args": ["/abs/path/to/examples/kunji-mcp/server.js"] }
  }
}
```

## Try it against the demo RP

1. Ask the assistant to call **`kunji_authorize`** with `audience: "kunji-demo.web.app"`,
   `scope: ["login"]`. It prints a request.
2. In the kunji wallet: **Security → Authorize an agent** → paste/scan that request →
   pick a TTL → **Approve** → copy the capability.
3. Give the capability to the assistant; it calls **`kunji_set_capability`**.
4. Ask it to call **`kunji_login`** with `baseUrl: "https://kunji-demo.web.app"` →
   it returns the verified `sub` + `scope`.

State (the agent key + current capability) is stored in `.mcp-state.json` (git-ignored).
Delete it to rotate the agent key.
