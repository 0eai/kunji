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
                                     → prints a 6-digit CODE + a QR + the raw request
 Security → "Authorize an agent"
   type the code (or scan the QR,
   or paste) → pick a TTL → Approve
        │  wallet relays the capability back, encrypted
        ▼
                                  kunji_await_capability()
                                     → polls the relay, decrypts + stores it (no copy/paste)
                                  kunji_login(baseUrl)
                                     → creates a session, signs its challenge with the
                                       agent key, POSTs /kunji/agent → { sub, scope, status }
```

The request reaches the wallet three equivalent ways — **type the 6-digit code** (works in a bare
terminal, no window needed), **scan the QR** (if the agent has a screen), or **paste** the raw JSON.
The code/QR carry no secret (just public keys + scope); the minted capability is ECDH-encrypted to the
agent's transport key and bound to its signing key, so a guessed code authorizes nothing.

Every sensitive step is gated: nothing works until **you** approve the capability in the
wallet, and the capability is bound to this agent's key (a stolen capability is useless),
scoped, and time-boxed. Revoke it from the wallet (Security → Authorized agents).

## Tools

| Tool | What it does |
|---|---|
| `kunji_authorize` | `{ audience, scope? }` → prints a 6-digit code + QR + request for you to approve in the wallet |
| `kunji_await_capability` | `{ sessionId? }` → poll the relay, decrypt + store the approved capability (no paste) |
| `kunji_set_capability` | `{ capability }` → manual fallback: store a pasted wallet-issued capability (validated) |
| `kunji_login` | `{ baseUrl }` → sign in at the RP as the authorized agent → `{ sub, scope, status }` |
| `kunji_stepup` | `{ scope, audience? }` → after a 403 insufficient_scope, ask the user for a broader scope (a delta-aware re-consent). Prints a same-device deep link + code + QR; then `kunji_await_capability` → `kunji_login` → retry |
| `kunji_request_via_push` | `{ channelId, scope?, audience? }` → ping the user's wallet via the opt-in Web Push relay (channel-less agents); then `kunji_await_capability` |
| `kunji_status` | the agent's public key + the loaded capability (audience/scope/expiry) |

### Step-up (asking for more access mid-task)

If the app returns **`403 insufficient_scope`**, call **`kunji_stepup`** with the broader scope (e.g.
`["login","read:profile"]`) — the user approves the *delta* in their wallet, then `kunji_await_capability`
→ `kunji_login` → retry. The agent **can't present your verified credentials itself** (it holds a
capability, not your keys); to prove one, step up with a **`vc:` scope** (e.g.
`["login","vc:age#age_over_18"]`) and *you* present it at the wallet re-consent.

For a **channel-less** agent (no way for the app to reach you), enable notifications for it when you
authorize (the wallet shows a channel id); the agent then uses **`kunji_request_via_push`** with that
channel id to nudge your wallet — the push carries only an opaque pointer.

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
   `scope: ["login"]`. It prints a 6-digit code, a QR, and the raw request.
2. In the kunji wallet: **Security → Authorize an agent** → **type the 6-digit code** (or scan
   the QR, or paste) → pick a TTL → **Approve**.
3. Ask the assistant to call **`kunji_await_capability`** — it receives the capability over the
   encrypted relay automatically (no copy/paste). (`kunji_set_capability` is the manual fallback.)
4. Ask it to call **`kunji_login`** with `baseUrl: "https://kunji-demo.web.app"` →
   it returns the verified `sub` + `scope`.

State (the agent key + current capability) is stored in `.mcp-state.json` (git-ignored).
Delete it to rotate the agent key.
