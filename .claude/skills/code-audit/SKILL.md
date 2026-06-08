---
name: code-audit
description: Re-run kunji's code-quality / maintainability audit lens (the C-numbered ledger) against the current code. Use when the user asks for a general/code/maintainability audit, to re-check code-quality findings, or to assess a change's structure/dead-code/dep/test impact. Owns the git-ignored reports/AUDIT.md (C# findings) — never commits it. This is the persistent-ledger counterpart to the one-off code-review skill; for security use security-audit, for hygiene use cleanup.
---

# Code-quality audit (kunji)

The maintainability counterpart to `security-audit`. The standing ledger is **`reports/AUDIT.md`
(C-numbered)** with a "Remediation status" table. It's **git-ignored — read and update locally,
never commit it.** Security findings (S#) belong to `security-audit`; pure hygiene (junk files,
`.gitignore`, secrets) belongs to `cleanup`.

## Before auditing: load the ledger

Read `reports/AUDIT.md`. Each finding is **Fixed**, **Mitigated**, or **Won't fix**. Don't re-report
an accepted decision (e.g. **C10** no service worker — intentional; **C7** theme-color synced by
cross-reference comments, not code). Note the prior re-sweeps so you extend, not duplicate.

## What to check (the maintainability lens)

1. **Automated-gate health.** `npm run lint` is the only gate that runs on every change and is
   hardened to `eslint . --max-warnings 0` — warnings creeping back (the **C16** class) silently
   erode it. `react-hooks/exhaustive-deps` regressions are the same family as the camera bug (**C2**).
2. **Dead code / unused deps.** No unreferenced modules or exports (the **C4** RSA-module class); no
   unused dependencies (the **C3** set stays gone). Grep before claiming dead — verify zero imports.
3. **Duplication & shared utilities.** Logic that exists once should stay once — `relTime` + the
   activity icon/colour maps live in `src/lib/activityFormat.js` (**C6**); a new copy is a finding.
4. **Error handling.** The `ErrorBoundary` around `<App/>` (**C5**) and actionable failure UI for
   anon-auth (**C8**) stay intact; services fail closed and map errors to toasts; `logActivity`
   swallows-and-warns so logging never breaks a flow.
5. **Bundle & splitting.** `npm run build` emits **no** >500 kB chunk warning (**C9** — vendor
   `manualChunks` + lazy `QRScannerOverlay`/`LinkDeviceScreen`). A new eager heavy import regresses it.
6. **Structure & clarity.** Layering holds (`lib/crypto → services → components`); naming/foldering
   consistent (`contexts/` not `context/`); no dead params, no stale `eslint-disable` directives,
   Prettier-clean.
7. **Test coverage.** Crypto round-trips, validators, and signer↔verifier/capability parity stay
   covered (`tests/`); a new protocol/serialization surface should arrive with a parity test.

## Method

- Scope to the diff for a change (`git diff`); full sweep only when asked to "audit everything."
- Verify every claim against `npm run lint && npm test && npm run build` before reporting — don't
  assert "dead"/"unused"/"duplicated" without the grep/build proof.
- Rank by leverage: a broken/eroding gate or a structural duplication > a nit.

## Output

Update `reports/AUDIT.md` (locally) with any new finding (assign the next **C#**) + status; record a
short dated re-sweep note of what was checked clean. Summarize to the user: confirmed findings with
severity + the proof, and what was verified clean. **Never commit `reports/`.**
