# AGENTS.md — kunji

Guidance for AI agents (and humans) maintaining this repo. Read this before editing.
`CLAUDE.md` is a symlink to this file. Deep protocol detail lives in `docs/discoverable-login.md`;
internal audit ledgers live in `reports/` (git-ignored — see constraints).

## What kunji is

A **client-only, zero-knowledge identity wallet**. Users unlock an on-device encrypted vault
with a passphrase; apps authenticate them by verifying a signed assertion the wallet POSTs
straight to the app's own callback. kunji runs **no backend in the login path** and the servers
store **only ciphertext**. There is no email/phone/name — sign-in is anonymous.

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

## Server-side write path (don't bypass)

- Clients **cannot** write vault docs directly — `firestore.rules` denies it (`write: if false`).
  All vault writes go through the **`vaultWrite`** Cloud Function via the `/vault/write` Hosting
  rewrite (`functions/index.js`, region `us-central1`, codebase `app`).
- `vaultWrite` validates: `vaultId` is 64-hex, `appId` matches `/^[A-Za-z0-9_-]{1,200}$/`
  (relaxed from hex to allow legacy random doc ids — see history), `op ∈ {set, delete}`, timestamp
  freshness, and an Ed25519 signature over canonical JSON. First write **TOFU-binds** the
  `writePublicKey`; later writes must match it.

## Standing constraints

- **Never commit `reports/`** — internal audit docs, git-ignored on purpose.
- **kunji shares no database with cloq or any other app.** Don't introduce cross-app data coupling.
- **Accepted, deliberate "won't-fix" risks** — do NOT "fix" these without asking; they're decisions,
  not oversights: CSP breadth (S11), `style-src 'unsafe-inline'`, the in-memory extractable master
  key, client-side freshness timestamp, recovery-key clipboard copy.
- **No git remote configured locally.** Pushing/publishing is the user's manual step.

## Repo map

- `src/lib/crypto/` — KDF, AES-GCM, Ed25519, canonical JSON. **Protocol; edit with extreme care.**
- `src/services/identity.js` — QR parsing, callback safety (`isSafeReturnUrl`), assertion submit,
  app register/delete, legacy migration.
- `functions/` — `vaultWrite` Cloud Function (codebase `app`, Node 20).
- `landing/` — marketing site + `rp.js` (the built drop-in "Sign in with kunji" widget).
- `widget/` — `rp.js` source (built with esbuild into `landing/`).
- `examples/kunji-login-demo/` — **separate Firebase project**; the RP reference implementation.
- `tests/` — Vitest (crypto round-trips, identity validators, wallet↔RP verifier cross-check).
- `docs/discoverable-login.md` — the full login protocol spec.

## Deploy topology (see the `deploy` skill for the procedure)

Firebase project `kunji-cc`, three Hosting targets: `app` → `app-kunji-cc` (app.kunji.cc),
`landing` → `kunji-cc` (kunji.cc), `redirect` → `kunji-xyz` (301 to kunji.cc). Functions: one
codebase `app`. The **demo is a different Firebase project** and is deployed independently — a
main-repo deploy never touches it.

## Workflow norms

- Before finishing any change: `npm run lint` && `npm test` && `npm run build` must be green.
  CI (`.github/workflows/ci.yml`) runs the same on push/PR.
- Commit messages end with the `Co-Authored-By` trailer; PR bodies end with the Claude Code line.
- Commit only when asked; branch off `main` first if needed.
