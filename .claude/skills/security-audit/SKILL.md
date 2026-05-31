---
name: security-audit
description: Re-run kunji's security/code audit lens against the current code. Use when the user asks to audit, re-check findings, review crypto/auth changes for regressions, or assess a new feature's security. References the git-ignored reports/ ledgers (S#/C# findings) — never commits them.
---

# Security audit (kunji)

kunji is a zero-knowledge crypto wallet — audit it as a **protocol**, not a typical web app. The
prior full audit lives in `reports/SECURITY_AUDIT.md` (S-numbered) and `reports/AUDIT.md`
(C-numbered), with "Remediation status" ledgers. These are **git-ignored — read and update locally,
never commit them.**

## Before auditing: load the ledgers

Read `reports/SECURITY_AUDIT.md` and `reports/AUDIT.md`. Each finding is marked **Fixed (Phase N)**,
**Fixed (close-out)**, or **Accepted — won't fix**. Don't re-report a known accepted risk as new.

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
7. **Secrets/PII.** No keys, tokens, or PII in committed code, logs, or the demo bundle.

## Method

- Scope to the diff when reviewing a change (`git diff`); do a full sweep only when asked to "audit
  everything."
- For non-trivial findings, **adversarially verify** before reporting: try to refute it, build the
  concrete repro/attack. Crypto findings especially produce plausible-but-wrong claims.
- Rank by real-world impact: a derivation/lockout regression > an auth bypass > a hardening nit.

## Output

Update the ledgers in `reports/` (locally) with any new finding (assign the next S#/C#) and its
status. Summarize to the user: confirmed findings with severity + repro, and explicitly note what
was checked and found clean. Never commit `reports/`.
