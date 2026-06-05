# Agentic delegation — design spec (DRAFT / not implemented)

> Status: **design only.** No code, no protocol change yet. This captures how an autonomous AI agent
> could act for a kunji user **without compromising security or anonymity**, for review before any
> implementation. The login protocol today is `docs/discoverable-login.md` (§6 assertion, §8.1
> default identity); this extends it.

## Why

Today kunji is strictly human-in-the-loop: an assertion is signed by the per-app key **only after the
user taps Approve** in the unlocked wallet (per-app private keys never leave the device; the master
key is in memory only). There is no API key, OAuth client-credentials, refresh token, or headless
credential — so an autonomous agent **cannot** authenticate for a user. That gate *is* the security
model. To support agents we must add a way to act on the user's behalf that keeps three invariants:

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
- `scope[]` — least-privilege action vocabulary (TBD — see open decisions).
- `iat`/`exp` — short-lived by default.
- `rateBudget`/`maxUses` — a per-capability ceiling the RP enforces.
- `jti` — opaque id for revocation.

### Issuance (wallet, explicit consent)
A new wallet flow: the user grants an agent a capability for **one app + scope**, time-boxed. The
wallet signs it with the per-app key (the key for that `sub`) and hands it to the agent out-of-band
(QR / paste / deep link). Master + per-app private keys stay on device.

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
A kunji **MCP server / local signing agent** exposes tools to an AI runtime (e.g. Claude), e.g.:

- `kunji.request_capability(audience, scope)` → triggers a **human approval** in the wallet, returns a
  capability;
- `kunji.sign(challenge)` → signs a challenge **only within a granted capability**.

The runtime never receives keys; every sensitive op is gated by a pre-authorized capability or a live
human approval. This is the practical "make agents work with kunji" surface.

## Open decisions (resolve before building)
- **Token format** — compact JWT-like vs macaroon/biscuit (the latter allows offline *attenuation*:
  an agent can narrow but never widen a capability).
- **Capability transport** to the agent (QR / paste / deep link / MCP channel).
- **Revocation ownership** — RP `jti` denylist vs short-TTL-only (backendless tension).
- **`scope` vocabulary** — the least-privilege action set apps and agents agree on.
- **Agent-traffic lane** — whether agent calls get an App Check exemption (revisits the deferred App
  Check decision in `docs/ops-cost-controls.md`).

## Next step
After this design is reviewed/approved, spin out an implementation plan: capability signer + RP
verifier (+ `tests/`), the wallet grant UI, and the MCP server — each behind the human-approval root.
