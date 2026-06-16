# @kunji/verify

Framework-agnostic, dependency-light verification for [kunji](https://kunji.cc) on the **relying-party
(RP) side**. kunji is a client-only, zero-knowledge identity wallet: the wallet POSTs a signed assertion
straight to your app's callback, and **your app verifies it locally** — kunji runs no backend in the login
path. This package is that verification, packaged.

- **Pure.** Node `crypto` + [`@noble/curves`](https://github.com/paulmillr/noble-curves) Ed25519 only. No
  Firebase, no network, no I/O, no framework.
- **Two products.** `verifyAssertion` (discoverable login) and `verifyCapabilityAssertion` (agentic
  delegation — a scoped, expiring, holder-of-key capability a user grants an AI agent).

```sh
npm i @kunji/verify
```

## Login — `verifyAssertion`

```js
import { verifyAssertion } from '@kunji/verify';

// `assertion` is the JSON the wallet POSTs to your callback. `session` is the login session you
// created (with its `challenge`, `expiresAt`, `status`). `audience` is YOUR origin — hardcode it
// server-side; never trust a body-supplied value (anti-relay/phishing).
const r = verifyAssertion({ assertion, session, audience: 'https://app.example.com' });
if (!r.ok) return reject(r.error); // e.g. 'audience_mismatch', 'bad_signature', 'stale_timestamp'

// r.sub is a STABLE, per-app, UNLINKABLE user id (hex SHA-256 of the per-app public key).
// r.claims is optional self-asserted profile { name?, picture? } — SIGNED but UNVERIFIED: treat as
// untrusted (HTML-escape name; render picture client-side only, never server-fetch it).
loginUser(r.sub, r.claims);
```

Single-use the session yourself: flip `status` to consumed inside a transaction (the verifier checks
`status === 'pending'`, but cannot enforce single-use across concurrent requests for you).

## Agents — `verifyCapabilityAssertion`

```js
import { verifyCapabilityAssertion, scopeSatisfies } from '@kunji/verify';

const r = await verifyCapabilityAssertion({
  capability, // the EdDSA-JWT capability the agent presents
  agentProof, // the agent's holder-of-key proof over your challenge
  audience: 'https://app.example.com',
  challenge, // your per-request nonce
  isRevoked, // optional: (jti) => bool — your operator denylist
  getRevocation, // optional: (jti) => { sig } | null — see "Revocation" below
});
if (!r.ok) return reject(r.error);

// r.sub chains to the same per-app identity as a human login. Enforce per-action:
if (!scopeSatisfies(r.scope, [{ id: 'payments:send', max: '50USD' }])) return forbid('insufficient_scope');
```

The capability is bound to the agent's key (`cnf.jwk`) — only the holder of that key can use it. kunji
**never** holds the agent's or user's keys.

## Revocation (advisory) — and why TTLs matter

kunji has no capability server in the agent↔RP path, so revocation is **advisory**: you check a denylist,
and the **short TTL is the real backstop**. `verifyCapabilityAssertion` gives you two optional hooks:

- `isRevoked(jti)` — a simple operator denylist (existence check).
- `getRevocation(jti)` — returns the user-initiated signed revocation `{ sig } | null`. A revocation
  counts **only** if `sig` (over `revokeMessage(jti)`) verifies against the capability's **own** per-app
  key — so a forged/bogus entry is ignored. Read it inside the same transaction you consume the request
  in (no TOCTOU), and reject on a fresh, signature-valid entry.

Because enforcement is advisory, **keep capabilities short-lived for sensitive scopes**. This package
ships guidance so you don't have to invent it:

```js
import { recommendedTtl, recommendedTtlForScopes, TTL_GUIDANCE } from '@kunji/verify';

recommendedTtl('payments:send'); // 300  (5 min)
recommendedTtl('read:orders'); //   86400 (24 h)
recommendedTtlForScopes(['read:orders', { id: 'payments:send', max: '50USD' }]); // 300 — the strictest wins
```

`TTL_GUIDANCE` (seconds): `payments`/`admin`/`delete` = 300, `write` = 3600, `read`/`profile` = 86400,
`default` = 3600. These are advisory for the **minting** side; the verifier always enforces the `exp` that
was actually minted. See [`docs/scope.md`](https://github.com/0eai/kunji/blob/main/docs/scope.md).

## API

| Export | Use |
| --- | --- |
| `verifyAssertion({ assertion, session, audience, now? })` | Verify a login assertion → `{ ok, sub, claims }` |
| `verifyCapabilityAssertion({ capability, agentProof, audience, challenge, now?, isRevoked?, getRevocation?, chain? })` | Verify an agent capability → `{ ok, sub, scope, jti }` |
| `scopeSatisfies(granted, required)` | Does the granted scope cover what an action requires? |
| `canonicalJson(obj)` · `subFromPublicKey(b64)` | The signing-contract primitives (key-sorted JSON; `sub` derivation) |
| `buildAgentProof(secretKey, { audience, challenge, capJti, now? })` · `revokeMessage(jti)` · `signJWS(header, claims, secretKey)` | Agent-side / tooling helpers |
| `recommendedTtl(scope)` · `recommendedTtlForScopes(list)` · `TTL_GUIDANCE` | Revocation-reliability TTL guidance |

All error results are `{ ok: false, error: '<reason>' }` with stable machine-readable reason strings.

## Note for kunji maintainers

This package is the **canonical source** of the RP verifier. The in-repo demo RPs mirror `src/verify.js`
and `src/capability.js` byte-for-byte (run `node scripts/sync-verify.js`); `tests/sdk.parity.test.js`
fails the build on any drift. Edit the verifier **here**, then sync.
