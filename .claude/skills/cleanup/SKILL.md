---
name: cleanup
description: Run kunji's production-readiness hygiene sweep — no junk tracked, gates green, .gitignore coverage, no secrets/PII, no debug/dead code. Use when the user asks to clean up the repo, make it production/ship/publish ready, or tidy before a release. Applies unambiguous fixes and flags judgment calls; it does NOT hunt bugs (security-audit) or maintainability issues (code-audit), and does NOT version/deploy (release/deploy).
---

# Cleanup — production readiness (kunji)

A repeatable "is this repo ready to ship" sweep. **Apply the safe, unambiguous fixes; flag anything
judgment-dependent.** This is *hygiene only* — defer bugs to `security-audit`, maintainability to
`code-audit`, and versioning/deploy to `release`/`deploy`.

## Know the intentional exceptions (do NOT delete or "fix" these)

- `landing/rp.js` + `landing/rp.v1.js` — the **built** widget (source in `widget/`), committed on purpose.
- `examples/*/package-lock.json` — committed deliberately for reproducible installs.
- `.firebaserc` (root + examples) — holds only **public** project IDs.
- The Firebase web `apiKey` in client config / `landing/rp.js` is **public — never a finding**.
- `examples/**` `console.log`s are intentional demo output — leave them.
- `reports/` is git-ignored audit ledgers — must **never** be staged.

## Checklist

1. **Tree & tracked artifacts.** `git ls-files` shows nothing junk tracked: no `dist/`,
   `node_modules/`, `.env*`, `*.pem`, `serviceAccount.json`, `.agent-key`, `.mcp-state.json`, scratch
   dirs. `git status` clean of stray files. (Cross-check against the exceptions above.)
2. **`.gitignore` coverage.** Root ignores `node_modules`, `dist`, `.env*`, `.firebase/`, `reports/`.
   **Safe-fix:** root currently lacks `.agent-key` / `.mcp-state.json` — add them as a fallback.
   Each `examples/*/.gitignore` should cover `node_modules`, `*.pem`, `serviceAccount.json`, and
   (agent/relay demos) `.agent-key` / `.mcp-state.json`.
3. **Debug / dead code — production paths only.** Grep `src/ widget/ functions/` for
   `console.log|console.debug|debugger|TODO|FIXME|XXX|HACK` → must be **zero**. Exclude lockfiles
   (`':!*package-lock.json'`) — base64 `integrity` hashes contain substrings like `XXX` and false-match.
   (`console.error`/`warn` are legitimate; `examples/**` demo logs are fine.)
4. **Dependency hygiene.** No reintroduced unused deps (the removed set: `dexie`, `uuid`,
   `@yudiel/react-qr-scanner`, `tailwindcss-animate`). Lockfile in sync. Optional: `npx depcheck`.
5. **Gate green.** `npm run lint && npm test && npm run build` (lint is `--max-warnings 0`), plus
   `npx prettier --check .` — the `format` script is write-only, so check formatting **non-mutating**.
6. **Secrets / PII.** No private keys, tokens, service-account JSON, or PII in tracked code, logs, or
   the built bundle (`dist/`, `landing/rp.js`). `git ls-files | grep -iE 'secret|credential|serviceAccount|\.pem|\.key'`.
7. **Docs coherence.** `AGENTS.md` repo map + `README.md` example list match what's on disk (e.g. all
   `examples/*` present). Defer the version bump / tag to `release`.

## Method & output

- Walk the checklist read-only first; **apply only unambiguous hygiene fixes** (e.g. a missing
  `.gitignore` line). Anything judgment-dependent (delete a file? change lockfile strategy?) → **flag,
  don't do.**
- Re-run the gate after any fix.
- Summarize as a short **pass/fail per item**: what was applied, what's flagged for the user, and what
  was checked clean. Never stage `reports/`.
