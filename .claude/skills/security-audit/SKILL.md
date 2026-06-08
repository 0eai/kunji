---
name: security-audit
description: Re-run kunji's security audit lens against the current code (crypto, auth, protocol, capabilities). Use when the user asks for a security audit/review, to re-check S# findings, or to assess a crypto/auth/capability change for regressions. Owns the git-ignored reports/SECURITY_AUDIT.md (S# findings) — never commits it. Code-quality (C#) is the code-audit skill's; repo hygiene/secrets sweeps are cleanup's.
---

# Security audit (kunji)

kunji is a zero-knowledge crypto wallet — audit it as a **protocol**, not a typical web app. This
skill owns the security ledger **`reports/SECURITY_AUDIT.md` (S-numbered)**, with a "Remediation
status" table. It's **git-ignored — read and update locally, never commit it.** Code-quality
findings (C#, `reports/AUDIT.md`) belong to the **`code-audit`** skill; pure hygiene (junk files,
`.gitignore`, secret-scanning the tree) belongs to **`cleanup`** — defer those rather than duplicating.

## Before auditing: load the ledger

Read `reports/SECURITY_AUDIT.md`. Each finding is marked **Fixed (Phase N)**, **Fixed (close-out)**,
or **Accepted — won't fix**. Don't re-report a known accepted risk as new. Note the dated re-sweeps
(through the agentic-delegation review, S18a–c / S19) so you extend, not duplicate.

## Accepted risks (decisions, NOT bugs — do not flag as findings)

- CSP breadth (S11) and `style-src 'unsafe-inline'`
- In-memory **extractable** master key
- Client-side freshness timestamp on signed writes
- Recovery-key clipboard copy

If a change *worsens* one of these, that's worth raising; their mere existence is not.

## What to check (the lens that matters here)

1. **Derivation stability.** Did anything change a salt, info string, hash, KDF param, or encoding in
   `src/lib/crypto/`? That re-keys existing users — treat as a **breaking regression**, not a nit.
   Cross-check against the invariants in `AGENTS.md`.
2. **Signer ↔ verifier parity.** Wallet `signWithEd25519` and RP `verify.js` must serialize canonical
   JSON identically. `tests/verify.test.js` is the guard — if assertion shape changed, confirm both
   sides + the test moved together.
3. **Callback / audience safety.** `parseQRPayload` + `isSafeReturnUrl` in `src/services/identity.js`:
   same-site/subdomain only, HTTPS (except localhost dev), no bare-TLD audience (public-suffix relay
   bypass), no `javascript:` URLs. `tests/identity.test.js` covers these — verify still passing.
4. **Vault write path.** `functions/index.js` `vaultWrite`: input validation (vaultId hex64, appId
   `SAFE_ID`, op allow-list, freshness), Ed25519 verification, TOFU `writePublicKey` binding intact.
   `firestore.rules` still denies direct client vault writes (`write: if false`).
5. **Firestore rules.** Owner-scoping on `users/{uid}`, vaults read-auth/write-false, `linkSessions`
   write-once + immutable `pubB`, `loginSessions` locked.
6. **Headers/CSP.** `firebase.json` + `public/theme-init.js` (external because CSP blocks inline
   scripts) — HSTS, frame-ancestors, no new inline-script regressions.
7. **Secrets/PII.** No keys, tokens, or PII in committed code, logs, or the demo bundle. (For a broad
   tree-wide secret/hygiene sweep, that's the `cleanup` skill — here, focus on crypto-material leaks.)
8. **Agentic delegation / capabilities.** `src/lib/capability.js`, `src/services/capability.js`, and
   the RP verifiers `examples/kunji-login-demo/functions/capability.js` +
   `examples/kunji-agent-demo/capability.js`. Check: JWS `alg` pinned (no `none`/alg-confusion);
   `sub` recomputed from the **signature-verified** header `jwk` (a forged cap only authenticates the
   attacker's *own* sub — no escalation); holder-of-key enforced (proof verified against `cnf.jwk`);
   proof `typ` + freshness + replay; `aud` checked on **both** cap and proof; scope non-empty;
   revocation honored only when issuer-signed (`revocations/{jti}` sig verifies against the cap's own
   key) and read inside the consume transaction (no TOCTOU); relay is **ciphertext-only**
   (ECDH-P256→AES-GCM, never plaintext at rest); wallet↔RP byte-parity (`tests/capability*.test.js`).

**Example RPs are template code devs clone** (`kunji-*-demo`, incl. `kunji-agent-demo`): re-apply the
example-scoped findings — security headers (S15), no inline `<script>` / real CSP (S16),
`claims.picture` scheme-gate + length bound (S17), and the agent demo's deliberately in-memory-only
revocation (S19, accepted/documented). A regression in a cloned template ships to every adopter.

## Method

- Scope to the diff when reviewing a change (`git diff`); do a full sweep only when asked to "audit
  everything."
- For non-trivial findings, **adversarially verify** before reporting: try to refute it, build the
  concrete repro/attack. Crypto findings especially produce plausible-but-wrong claims.
- Rank by real-world impact: a derivation/lockout regression > an auth bypass > a hardening nit.

## Output

Update `reports/SECURITY_AUDIT.md` (locally) with any new finding (assign the next **S#**) and its
status; add a dated re-sweep note of what was checked clean. Summarize to the user: confirmed
findings with severity + repro, and explicitly note what was checked and found clean. A code-quality
issue surfaced in passing → hand it to `code-audit` (don't open a C# here). **Never commit `reports/`.**
