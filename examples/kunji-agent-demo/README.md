# kunji-agent-demo

A framework-free, Firebase-free **relying party** (RP) that accepts **both**:

- **human logins** — the §6 discoverable-login assertion (the drop-in widget), and
- **agent logins** — a holder-of-key **capability** minted by the user's wallet (agentic
  delegation, see [`docs/agentic-delegation.md`](../../docs/agentic-delegation.md)).

It's [`kunji-node-demo`](../kunji-node-demo) plus one endpoint — `POST /kunji/agent` — so you can
point an agent (the bundled simulator, or the real [`kunji-mcp`](../kunji-mcp) bridge) at a real,
runnable RP with zero infra. Plain Node `http` + an in-memory session `Map` + two verifiers
([`verify.js`](verify.js) for assertions, [`capability.js`](capability.js) for capabilities). There
is **no kunji server in the login path**.

> `verify.js` and `capability.js` are byte-for-byte copies of the test-guarded protocol verifiers
> (`examples/kunji-node-demo/verify.js` and `examples/kunji-login-demo/functions/capability.js`).
> They are a signing contract with the wallet — don't edit them here.

## Endpoints

| Method + path          | Who calls it        | What it does                                              |
| ---------------------- | ------------------- | --------------------------------------------------------- |
| `POST /api/session`    | widget **or** agent | mint `{ sessionId, challenge, audience, callbackUrl, … }` |
| `POST /kunji/callback` | the wallet (human)  | verify the §6 signed assertion, approve the session       |
| `POST /kunji/agent`    | an agent            | verify `{ capability, agentProof }`, approve the session  |
| `GET  /kunji/status`   | the frontend        | poll `{ status, sub, claims, scope, agent }`              |
| `POST /agent/start`    | the page (as agent) | get a 6-digit code + QR from the relay for the user to authorize |
| `GET  /agent/poll`     | the page            | once approved, decrypt the relayed capability + log in here; returns the I/O |

An agent login resolves to the **same `sub`** a human login would — the agent acts as the user, on
a scoped, expiring, revocable capability. `status.agent` distinguishes how the session was approved.

The agent half of the flow lives in [`agent-client.js`](agent-client.js) (mirrors the kunji-mcp
bridge): build a v2 request + ECDH transport key, get a code/QR from `app.kunji.cc/agent/request`,
poll `app.kunji.cc/agent/capability`, decrypt, then log in. Both the web page and `agent-sim.js`
use it. Override the relay with `KUNJI_APP_URL` (defaults to `https://app.kunji.cc`).

## 1. Run the RP

```sh
npm install
npm start              # http://localhost:3000
```

For a **real phone** (a wallet rejects untrusted certs on non-localhost hosts) serve HTTPS with a
device-trusted cert:

```sh
mkcert -cert-file cert.pem -key-file key.pem <your-lan-ip> localhost
TLS_KEY=./key.pem TLS_CERT=./cert.pem npm start
```

`localhost` over plain HTTP is fine for both the wallet PWA and the agent.

## 2. Human login

Open `http://localhost:3000`, click **Sign in with kunji**, and approve in your wallet. The page
shows your per-app identity (the default `kunji.handle(sub)` name + icon, or a profile you shared).

The dialog offers **QR**, an **OTP** code (type it into the wallet), and a same-device **Sign in with
kunji** button. Note: the phone-facing paths (QR scan + OTP) only work end-to-end when the wallet can
reach this RP — i.e. when it's served over **HTTPS at a real host** (see §1's mkcert/tunnel steps).
On plain `http://localhost` the production wallet can't reach it, so use the **same-device button** or
the agent path below.

## 3. Agent login — three ways

Every way, the capability's **`audience` must equal this RP's hostname** (`localhost` by default;
whatever is in `BASE`/`PUBLIC_ORIGIN` otherwise). The wallet derives the per-app key from it.

### a) In the browser (the page acts as a web-hosted agent — QR + OTP)

Open `http://localhost:3000` → **"Authorize an agent →"**. The page asks the relay for a **6-digit
code + QR**; in your wallet do **Security → Authorize an agent**, type the code (or scan), Approve.
The page receives the capability over the encrypted relay, logs itself in here, and shows the
verified `sub` plus the **raw request/response** that crossed the wire.

### b) Headless simulator (live QR + OTP relay — no copy/paste)

```sh
node agent-sim.js
```

Prints a **6-digit code**, a **terminal QR**, and the raw request. Authorize in the wallet (type the
code or scan); the simulator receives the capability over the relay and logs in:

```
✓ capability received over the relay
agent login → { status: 'ok' }
session    → { status: 'approved', sub: '…', scope: [ 'login' ], agent: true }
```

Offline / relay-down fallback (paste a capability, no relay):

```sh
node agent-sim.js                          # copy the printed request → wallet → copy the capability
CAP="<capability JWT>" node agent-sim.js   # log in with the pasted capability
```

### c) Real MCP bridge

Run this RP, then drive the [`kunji-mcp`](../kunji-mcp) bridge with the relay pointed at the hosted
app and `baseUrl` pointed here:

```
KUNJI_APP_URL=https://app.kunji.cc        # the capability relay
kunji_authorize        { audience: "localhost", scope: ["login"] }
# → type the code (or scan the QR) in your wallet (Security → Authorize an agent)
kunji_await_capability                      # wallet delivers it over the encrypted relay
kunji_login            { baseUrl: "http://localhost:3000" }
# → { status: "approved", sub, scope }
```

## Notes

- **Revocation.** This demo enforces an in-memory operator denylist (`revoked` `Set` in
  [`server.js`](server.js)); the capability's short TTL is the backstop. It does **not** check the
  kunji-hosted, issuer-signed revocation list (that needs a fetch to `app.kunji.cc`) — see
  `examples/kunji-login-demo/functions/index.js` for that variant.
- **The agent never sees kunji keys** — only a scoped capability bound to *its own* key, plus a
  proof it holds that key. A stolen capability is useless without the agent's private key.
