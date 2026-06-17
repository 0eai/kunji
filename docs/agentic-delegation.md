# Agentic delegation — protocol (shipped)

> **Status: shipped.** How an autonomous AI agent acts for a kunji user **without compromising
> security or anonymity** — see "Status — shipped" below and `src/lib/capability.js`. It extends the
> login protocol in `docs/discoverable-login.md` (§6 assertion, §8.1 default identity).

## Why

Today kunji is strictly human-in-the-loop: an assertion is signed by the per-app key **only after the
user taps Approve** in the unlocked wallet (per-app private keys never leave the device; the master
key is in memory only). There is no API key, OAuth client-credentials, refresh token, or headless
credential — so an autonomous agent **cannot** authenticate for a user. That gate *is* the security
model. Supporting agents therefore needs a way to act on the user's behalf that keeps three invariants:

1. **The agent never holds kunji keys** (master key or per-app private keys).
2. **Per-app unlinkability** is preserved (no global agent identifier, no kunji-side correlation).
3. **A human authorizes the grant**; agents act only inside a pre-approved, narrow, revocable scope.

## Model — capabilities, not keys

Replace "give the agent access" with "the user signs the agent a **capability**".

### Capability token
kunji-signed by the existing **per-app key** for an audience `D` (reuse the canonical-JSON + Ed25519
signer in `src/lib/crypto/ed25519.js`; an RP verifies it exactly like a §6 assertion). It is
**holder-of-key**, not bearer — bound to the agent's own ephemeral public key, so a leaked capability
is useless without the agent's private key. Fields:

```
{ v, audience, agentPubKey, scope[], iat, exp, rateBudget|maxUses, jti }
```

- `audience` — the app/domain this grant is for (same normalization as §5/§8).
- `agentPubKey` — the agent's ephemeral key (holder-of-key binding).
- `scope[]` — least-privilege action vocabulary; the grammar + `scopeSatisfies` + delegation-chain
  attenuation shipped in Phase 1 (see [`scope.md`](./scope.md)).
- `iat`/`exp` — short-lived by default.
- `rateBudget`/`maxUses` — a per-capability ceiling the RP enforces.
- `jti` — opaque id for revocation.

### Issuance (wallet, explicit consent)
The wallet flow — Security → "Authorize an agent" (`src/components/AuthorizeAgentSheet.jsx` +
`src/services/capability.js`): the user grants an agent a capability for **one app + scope**,
time-boxed. The wallet signs it with the per-app key (the key for that `sub`) and delivers it to the
agent out-of-band (encrypted relay, QR, or paste). Master + per-app private keys stay on device.

### Presentation & verification (RP-side, backendless)
The agent signs a fresh RP challenge with `agentPubKey` and presents the capability. The RP verifies,
locally (no kunji server in the path — same trust model as §6):

1. the capability signature chains to the user's per-app public key → the **same `sub`** the app
   already knows;
2. **holder-of-key**: the challenge was signed by `agentPubKey`;
3. `audience`, `scope`, `iat`/`exp` are valid;
4. `jti` is not revoked, and the `rateBudget` isn't exceeded.

### Anonymity
Per-app key derivation is unchanged. A capability is per **(user, app, agent)** and **unlinkable
across apps**; there is no global agent identifier and no kunji-side registry. Optionally derive a
distinct per-(app, agent) sub so the app can treat/limit/audit the agent as a related-but-distinct
principal from the human.

### Revocation & abuse
RP-side `jti` denylist (keeps kunji backendless) + a short default TTL as the safety net. The
`rateBudget` is RP-enforced and ties directly into the function cost-hardening
(`docs/ops-cost-controls.md`) since agent traffic is automated.

## MCP bridge (how an AI runtime drives kunji)
A kunji **MCP server / local signing agent** exposes tools to an AI runtime (e.g. Claude). Built at
**`examples/kunji-mcp/`** (stdio MCP server, `@modelcontextprotocol/sdk`):

- `kunji_authorize(audience, scope)` → builds the request and presents three ways for the user to
  bring it into their wallet: a **6-digit code** (printed in the terminal — type it in the wallet),
  a **terminal QR** (scan it), and the raw JSON (paste fallback);
- `kunji_await_capability(sessionId?)` → polls the relay, decrypts the wallet-deposited capability with
  the agent transport key, validates it (holder-of-key + expiry), and stores it — no copy/paste;
- `kunji_set_capability(capability)` → manual fallback: stores a pasted wallet-issued capability
  (validated holder-of-key + expiry);
- `kunji_login(baseUrl)` → signs the RP challenge with the agent key **only within the granted
  capability** and submits it;
- `kunji_stepup(scope, audience?)` → after a `403 insufficient_scope`, requests a **broader scope** on a
  connected app (incl. a `vc:` scope to have the user present a verified credential — the agent can't
  present the user's holder-bound credentials itself). Returns a same-device deep link (Transport ①) +
  code + QR; the wallet shows a delta-aware re-consent; then `kunji_await_capability` → `kunji_login` → retry;
- `kunji_request_via_push(channelId, scope?, audience?)` → for a **channel-less** agent the user enabled
  notifications for: pings the wallet over the opt-in Web Push relay (Transport ②, opaque pointer only);
- `kunji_status` → the agent's public key + the loaded capability.

### Request hand-off — QR + OTP (no JSON pasting)
The request → wallet hop has three equivalent entry points (the return hop is always the encrypted
relay above). The request object is:

```json
{ "kunjiCap": "v2", "audience": "example.com", "scope": ["login"],
  "agentPub": "<base64 Ed25519 pub>", "transportPub": "<base64 ECDH-P256 SPKI>",
  "sessionId": "<64-hex>" }
```

- **OTP (headless-friendly)** — the agent `POST`s the request to `https://app.kunji.cc/agent/request`
  (the `agentRequestRelay` function) and gets back a short **6-digit code** stored under
  `agentRequests/{code}` with a ~3-min TTL; the user types it in the wallet, which `GET`s it back by
  code. Works in a bare terminal — no window or page needed.
- **QR** — for an agent with a display (terminal QR, or a web-hosted agent's popup), render the request
  JSON as a QR; the wallet scanner ingests it directly.
- **Paste** — the raw JSON, unchanged.

**Portfolio request (4.2) — N apps in one approval.** A shopping/concierge agent that needs to act at
*several* apps can batch them into a single review with a `portfolio-v1` request — one shared agent key +
transport key, an `items[]` of per-app `{audience, scope, sessionId}` (≤10, distinct audiences):

```json
{ "kunjiCap": "portfolio-v1", "agentPub": "<base64 Ed25519 pub>",
  "transportPub": "<base64 ECDH-P256 SPKI>", "label": "Concierge",
  "items": [ { "audience": "shop.example",  "scope": ["login"], "sessionId": "<64-hex>" },
             { "audience": "travel.example","scope": ["login","read:profile"], "sessionId": "<64-hex>" } ] }
```

It opens the wallet's **multi-app review** (deep link `?authorize=` or scan); the user approves once and the
wallet mints **N independent per-app capabilities** — each signed by its own per-app key, deposited to its
own `sessionId`, recorded under its own `jti`. This is **not** a single cross-app grant (that would break
unlinkability); it's purely a batched UX over the single-app flow, so each app still sees an unrelated `sub`.
The agent polls each item's `sessionId` exactly as in the single-app flow.

The code/QR carry **no secret** (only public keys + scope): the minted capability is ECDH-encrypted to
`transportPub` and bound to `agentPub`, so a guessed/leaked code authorizes nothing. The relay is
per-IP rate-limited and the code is short-TTL + function-mediated both ways (`agentRequests/{code}` is
`read,write:if false`; demo-grade caveat mirrors the link/login OTP).

The runtime never receives keys; the agent's keypair lives only on the local machine; every sensitive
op is gated by a pre-authorized capability or a live human approval. This is the practical "make
agents work with kunji" surface.

## Status — shipped

Implemented across the wallet, the protocol core, the RP verifiers, and the MCP bridge:

- **Protocol core** (mint / agent-proof / verify): `src/lib/capability.js` + `tests/capability.test.js`.
- **Wallet grant UI**: `src/services/capability.js` + `src/components/AuthorizeAgentSheet.jsx`
  (Security → "Authorize an agent").
- **RP verification**: `examples/kunji-login-demo/functions/capability.js` (Firebase) and
  `examples/kunji-agent-demo/capability.js` (plain Node, no Firebase — `POST /kunji/agent` on top of
  the §6 login RP) + a revocation denylist; `tests/capability.parity.test.js` cross-checks
  wallet-mint ↔ RP-verify. Headless demos: `examples/kunji-login-demo/agent-sim.js` and
  `examples/kunji-agent-demo/agent-sim.js`.
- **MCP bridge**: `examples/kunji-mcp/` (see its README) — runnable end-to-end against
  `examples/kunji-agent-demo` with zero infra.

### Decisions resolved while building
- **Capability transport (v0.6.0)** — the agent presents an ECDH transport key + session id in its
  request; the wallet deposits the capability **ECDH-encrypted** into a short-TTL `agentSessions/{id}`
  relay; the agent polls the public `agentCapabilityPoll` function and decrypts. Paste/QR remains a
  fallback. (`src/services/capability.js` `depositAgentCapability`, `examples/kunji-mcp` `awaitCapability`.)
- **Request hand-off (v0.12.0)** — QR + 6-digit OTP via the `agentRequestRelay` function, so the
  request reaches the wallet without pasting JSON (see "Request hand-off" above).
- **Revocation ownership (v0.7.0)** — issuer-signed, kunji-hosted denylist. The wallet signs
  `kunji-revoke-v1:{jti}` with the per-app key and publishes the (public-read) `revocations/{jti}`; a
  cooperating RP honors it only if the signature verifies against the **capability's own key** (so only
  the issuer can revoke; forged entries are ignored). A short default TTL stays as the backstop for RPs
  that don't check. (`src/services/capability.js` `revokeAgent` ↔ verifier `getRevocation`.)
- **Scope vocabulary + attenuation (Phase 1)** — the scope grammar (string | `{id,...constraints}`),
  reserved core + namespacing, the backendless `scopeSatisfies` enforcer (mirrored across the RP
  verifiers), per-item consent, and delegation-chain attenuation (`kunji-capdel+jwt`,
  narrow-not-widen). Design: [`scope.md`](./scope.md).

### Still open / deferred
- **Step-up / incremental authorization** — **shipped** (wallet re-consent via Transport ① deep link +
  Transport ② push) and now **exposed in the MCP bridge** (`kunji_stepup`, `kunji_request_via_push`). A
  connected agent requesting more scope (or a `vc:` credential the user presents) later. See
  [`push-relay.md`](./push-relay.md), [`verified-credentials.md`](./verified-credentials.md).
- **Token format** — compact JWT-like (today) vs macaroon/biscuit, which would allow offline
  *attenuation* (an agent narrows but never widens a capability).
- **Agent-traffic lane** — whether agent calls get an App Check exemption (revisits the deferred App
  Check decision in `docs/ops-cost-controls.md`).
