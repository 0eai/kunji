# AGENTS.md — kunji

Guidance for AI agents (and humans) maintaining this repo. Read this before editing.
`CLAUDE.md` is a symlink to this file. Deep protocol detail lives in `docs/discoverable-login.md`;
internal audit ledgers live in `reports/` (git-ignored — see constraints).

## What kunji is

A **client-only, zero-knowledge identity wallet**. Users unlock an on-device encrypted vault
with a passphrase; apps authenticate them by verifying a signed assertion the wallet POSTs
straight to the app's own callback. kunji runs **no backend in the login path** and the servers
store **only ciphertext**. There is no email/phone/name — sign-in is anonymous. Beyond human login,
a user can authorize an AI **agent** to act for them at one app via a scoped, expiring, revocable,
holder-of-key capability — never the keys (agentic delegation, shipped).

- App: https://app.kunji.cc · Site: https://kunji.cc · Demo: https://kunji-demo.web.app
- Stack: Vite + React 19 PWA, Tailwind v4, Firebase (anon Auth, Firestore, Hosting multi-site,
  Functions 2nd-gen). Crypto: hash-wasm (Argon2id), WebCrypto (AES-GCM), @noble/curves (Ed25519).

## ⚠️ Crypto invariants — DO NOT break these

These are **load-bearing and silent**: breaking one doesn't fail a test you'll notice — it locks
existing users out of their vaults or breaks every app's login. Treat `src/lib/crypto/` and
`src/services/identity.js` as a protocol, not ordinary code.

- **Deterministic derivation.** `deriveAppKeyPair(masterKey, domain)` and `deriveVaultId(masterKey)`
  must stay byte-for-byte stable forever. Changing a salt, info string, hash, or KDF param
  *re-keys every existing user*. Never "tidy up" these.
- **`sub = hex(SHA-256(utf8(publicKeyBase64)))`.** This is the identity an app sees. Stable per
  (vault, domain); unrelated across domains (unlinkability). Don't change the hash or encoding.
- **Canonical JSON is the signing contract.** `signWithEd25519` signs canonical (key-sorted) JSON,
  so signatures are key-order independent. The wallet signer and the RP verifier
  (`examples/kunji-login-demo/functions/verify.js`) MUST serialize identically — `tests/verify.test.js`
  cross-checks this. Any change to serialization must change both sides together.
- **Domain normalization at the derivation boundary** (`normalizeDomain`): lowercase, trim, strip
  trailing dot, collapse default ports (`:443`/`:80`). So `Example.com`, `example.com.`,
  `example.com:443` are one identity. Apply it at derivation only — don't change identity semantics.
- **Argon2id is per-device and migration is guarded.** Params are stored per user
  (`ARGON2_DEFAULTS` = m:262144/t:4/p:1 = 256MB; `ARGON2_LEGACY` = 64MB/t:3/p:1). The V2 re-wrap is
  only persisted if the 256MB derive *succeeds on that device* — weak devices stay on legacy params
  and are never locked out. Don't make the upgrade unconditional.
- **Key separation.** Per-app keys, the vault-write keypair, and the vaultId are independent
  HKDF derivations from the master key. Keep them distinct.
- **The default-identity algorithm is a rendering contract.** `src/lib/kunjiHandle.js` +
  `kunjiHandle.wordlists.js` derive a display name + identicon from `sub`, and the wallet, `rp.js`,
  the demo, and third-party RPs must all produce identical output (it's specified in
  `docs/discoverable-login.md` §8.1). Changing the algorithm or wordlist length/order re-skins every
  user's default name/avatar — cosmetic (never a lockout, `sub` is unchanged) but a versioned break.
  Keep the module pure and dependency-free.

## Server-side write path (don't bypass)

- Clients **cannot** write vault docs directly — `firestore.rules` denies it (`write: if false`).
  All vault writes go through the **`vaultWrite`** Cloud Function via the `/vault/write` Hosting
  rewrite (`functions/index.js`, region `us-central1`, codebase `app`).
- `vaultWrite` validates: `vaultId` is 64-hex, `appId` matches `/^[A-Za-z0-9_-]{1,200}$/`
  (relaxed from hex to allow legacy random doc ids — see history), `op ∈ {set, delete}`, timestamp
  freshness, and an Ed25519 signature over canonical JSON. First write **TOFU-binds** the
  `writePublicKey`; later writes must match it.
- `vaultWrite` also handles `kind: 'profile'` → writes the user's optional custom profile to
  `vaults/{vaultId}/profile/self`. `kind` is signed only when present, so existing app writes stay
  byte-identical. The login assertion may now carry an optional `claims` object (custom name/avatar)
  — signed but **self-asserted and unverified**; RPs must treat it as untrusted. The zero-config
  default identity (`kunjiHandle`) needs none of this.

## Standing constraints

- **Never commit `reports/`** — internal audit docs, git-ignored on purpose.
- **kunji shares no database with cloq or any other app.** Don't introduce cross-app data coupling.
- **Accepted, deliberate "won't-fix" risks** — do NOT "fix" these without asking; they're decisions,
  not oversights: CSP breadth (S11), `style-src 'unsafe-inline'`, the in-memory extractable master
  key, client-side freshness timestamp, recovery-key clipboard copy.

## Repo map

- `src/lib/crypto/` — KDF, AES-GCM, Ed25519, canonical JSON. **Protocol; edit with extreme care.**
- `src/lib/kunjiHandle.js` (+ `.wordlists.js`) — deterministic default identity (name + identicon)
  from `sub`. **Shared rendering contract** (also bundled into `rp.js`); pure, dependency-free.
- `src/services/profile.js` + `src/components/ProfileSettings.jsx` — the optional custom profile
  (Layer 2): encrypted vault storage + the editor in `SecurityPanel`.
- `src/services/identity.js` — QR parsing, callback safety (`isSafeReturnUrl`), assertion submit,
  app register/delete, legacy migration.
- `functions/` — `vaultWrite` Cloud Function (codebase `app`, Node 20).
- `landing/` — marketing site + `rp.js` (the built drop-in "Sign in with kunji" widget).
- `widget/` — `rp.js` source (built with esbuild into `landing/`).
- `examples/` — reference relying parties: `kunji-login-demo` (Firebase; same project `kunji-cc`,
  site `kunji-demo`, default functions codebase), `kunji-node-demo` (plain Node, no Firebase),
  `kunji-agent-demo` (plain Node, no Firebase — like `kunji-node-demo` but also accepts **agent**
  capability logins via `POST /kunji/agent`; the runnable target for `kunji-mcp` / `agent-sim.js`),
  `kunji-relay-demo` (local RP + thin public callback Function, for real-phone testing with no tunnel),
  `kunji-selfhosted-demo` (production self-hosted: own Firebase + custom domain + custom token, on-prem
  worker on a dynamic IP). The last four are **not** deployed into `kunji-cc` — selfhosted in
  particular needs its own project (it mints Auth users / writes `users/{sub}`); don't deploy it here.
  `kunji-mcp` is a local **MCP bridge** (stdio server) that lets an AI runtime act for a user via a
  user-authorized, holder-of-key **capability** — never the keys (agentic delegation — shipped, v0.12.0).
- `src/lib/capability.js` — agentic-delegation capability tokens (EdDSA-JWT, holder-of-key); see
  `docs/agentic-delegation.md`. RP verifier mirrored in `examples/kunji-login-demo/functions/capability.js`.
- **Step-up authorization** (push-relay.md Transport ①): a same-device deep link
  `app.kunji.cc/?authorize=<base64url(JSON agent request)>` (`src/App.jsx` `readIncomingLinks`) opens
  `AuthorizeAgentSheet` straight to a **delta-aware** review (`initialRequest` prop: "already connected"
  banner, new-vs-granted per item, revoke-prior). The RP loop (`403 insufficient_scope` → re-request →
  retry) is shown in `examples/kunji-agent-demo` (`agent-sim.js` + the `/agent/stepup` browser demo).
  No new Function/rule — it reuses `agentRequestRelay`/`agentCapabilityPoll`.
- `tests/` — Vitest (crypto round-trips, identity validators, wallet↔RP verifier cross-check,
  capability mint/verify + wallet↔RP parity).
- `docs/discoverable-login.md` — the full login protocol spec; `docs/agentic-delegation.md` — agents.
  Implemented: `docs/scope.md` (Phase 1 scope engine), `docs/verified-credentials.md` (Phases 2–3
  verified credentials), `docs/push-relay.md` **Transport ①** (step-up authorization — re-consent
  via deep link, no new infra), and `docs/oid4vc.md` (**OpenID4VCI/VP interop**, headless — envelope
  lib + demo endpoints + sim; wallet UI is the follow-on). Proposed (not implemented):
  `docs/push-relay.md` **Transport ②** (the opt-in Web Push relay).
- `src/services/credentials.js` + `src/components/CredentialsSheet.jsx` — verified credentials the
  user holds (receive/list/present); stored via `vaultWrite kind:'credential'`; issuance relay =
  `credentialOfferRelay` (issuer deposit) + `credentialPoll` (wallet poll). RP verifier `vc.js` is a
  byte-identical Node port across `kunji-{node,issuer,login}-demo` (parity-guarded).
- `src/lib/oid4vc.js` — **OpenID4VCI/VP interop** envelope over `vc.js` (offer/proof/token for issuance;
  presentation_definition/vp_token/direct_post for presentation); pure, no new crypto. Byte-identical Node
  port in `kunji-{node,issuer}-demo/oid4vc.js` (parity-guarded). Demos: issuer OpenID4VCI endpoints
  (`kunji-issuer-demo/oid4vci.js` + routes), the OID4VP verifier routes in `kunji-node-demo/server.js`,
  and the headless holder `kunji-node-demo/oid4vc-sim.js` (`npm run oid4vc`). **Wallet UI**:
  `src/services/credentials.js` `receiveViaOffer`/`presentViaOid4vp`, an offer entry in
  `CredentialsSheet.jsx`, and `PresentCredentialSheet.jsx` (opened from `Dashboard.handleQRScan` on an
  `openid4vp://` scan or the `?vp=` deep link in `src/App.jsx`). **Verifier auth + DCQL**: OpenID4VP
  signed request objects verified against the verifier's `.well-known/kunji-verifier.json`
  (`buildSignedAuthorizationRequest`/`verifyRequestObject`, the HTTPS-anchored `client_id` scheme;
  `fetchVerifierKeys`) + DCQL queries (`buildDcqlQuery`/`requestQuery`/`buildVpResponse`). See `docs/oid4vc.md`.

## Deploy topology (see the `deploy` skill for the procedure)

Firebase project `kunji-cc`, three root Hosting targets: `app` → `app-kunji-cc` (app.kunji.cc),
`landing` → `kunji-cc` (kunji.cc), `redirect` → `kunji-xyz` (301 to kunji.cc). The app's `vaultWrite`
lives in Functions **codebase `app`**. The demo (`examples/kunji-login-demo/`) is in the **same
project** but deploys from its own `firebase.json` (`cd` into it): Hosting site `kunji-demo`, and its
four functions in the **default** codebase — codebase-isolated from `app`, so deploying one never
prunes the other. That isolation is load-bearing: always deploy functions with explicit `--only`.

## Workflow norms

- Before finishing any change: `npm run lint` && `npm test` && `npm run build` must be green.
  CI (`.github/workflows/ci.yml`) runs the same on push/PR.
- Commit messages end with the `Co-Authored-By` trailer; PR bodies end with the Claude Code line.
- Commit only when asked; branch off `main` first if needed. Remote `origin` →
  `github.com:0eai/kunji`; push only when asked.
