---
name: cleanup
description: Run kunji's production-readiness hygiene sweep — no junk tracked, gates green, .gitignore coverage, no secrets/PII, no debug/dead code. Use when the user asks to clean up the repo, make it production/ship/publish ready, or tidy before a release. Applies unambiguous fixes and flags judgment calls; it does NOT hunt bugs (security-audit) or maintainability issues (code-audit), and does NOT version/deploy (release/deploy).
---

# Cleanup — production readiness (kunji)

A repeatable "is this repo ready to ship" sweep. **Apply the safe, unambiguous fixes; flag anything
judgment-dependent.** This is *hygiene only* — defer bugs to `security-audit`, maintainability to
`code-audit`, and versioning/deploy to `release`/`deploy`.

## Know the intentional exceptions (do NOT delete or "fix" these)

- `landing/rp.js`, `landing/rp.v1.js`, `landing/rp-*.js`, `landing/rp.versions.json` — the **built**
  widget + its published SRI manifest (source in `widget/`), committed on purpose. The `rp-*.js` files
  are **immutable published artifacts** — never delete or regenerate one; RPs pin their hashes.
- `examples/*/package-lock.json` — committed deliberately for reproducible installs.
- `.firebaserc` (root + examples) — holds only **public** project IDs.
- The Firebase web `apiKey` in client config / `landing/rp.js` is **public — never a finding**.
- `examples/**` `console.log`s are intentional demo output — leave them.
- Audit ledgers live **outside the repo** (`~/.local/share/kunji/reports/`), so there is nothing to
  stage. If a `reports/` directory reappears in the tree, that's a finding — move it back out.

## Checklist

1. **Tree & tracked artifacts.** `git ls-files` shows nothing junk tracked: no `dist/`,
   `node_modules/`, `.env*`, `*.pem`, `serviceAccount.json`, `.agent-key`, `.mcp-state.json`, scratch
   dirs. `git status` clean of stray files. (Cross-check against the exceptions above.)
2. **`.gitignore` coverage.** Root ignores `node_modules`, `dist`, `.env*`, `.firebase/`, `reports/`.
   **Safe-fix:** root currently lacks `.agent-key` / `.mcp-state.json` — add them as a fallback.
   Each `examples/*/.gitignore` should cover `node_modules`, `*.pem`, `serviceAccount.json`, and
   (agent/relay demos) `.agent-key` / `.mcp-state.json`.
3. **Debug / dead code — production paths only.** Must be **zero**:

   ```bash
   git grep -nE 'console\.log|console\.debug|debugger|TODO|FIXME|XXX|HACK' \
     -- src widget functions issuer-functions \
     ':!*package-lock.json' ':!widget/publish.js' ':!issuer-functions/scripts/**'
   ```

   The exclusions are deliberate, not laziness: lockfiles false-match because base64 `integrity`
   hashes contain substrings like `XXX`; `widget/publish.js` and `issuer-functions/scripts/**` are
   build tooling and operator CLIs whose stdout **is** their product (`publish.js` prints the SRI
   hash an integrator pastes). (`console.error`/`warn` are legitimate; `examples/**` demo logs
   are fine.)
4. **Dependency hygiene.** No reintroduced unused deps (the removed set: `dexie`, `uuid`,
   `@yudiel/react-qr-scanner`, `tailwindcss-animate`). Lockfile in sync. Optional: `npx depcheck`.
5. **Gate green.** `npm run lint && npm test && npm run build` (lint is `--max-warnings 0`). For
   formatting, check only the files the change **adds** — never repo-wide, and not merely-touched
   files either:

   ```bash
   git diff --name-only --diff-filter=A main...HEAD \
     | grep -E '\.(js|jsx|md|json|css)$' | xargs -r npx prettier --check
   ```

   `--diff-filter=A` (added), not `ACM` (added/copied/modified), is the load-bearing part. On a
   long-lived branch `ACM` re-flags every pre-existing unformatted file the branch happened to touch —
   24 files vs 2 on a real sweep, which is noise, not signal. A **new** file has no legacy excuse and
   should be born formatted; existing files wait for the reformat decision below.

   **Do not run `prettier --write .`** and do not treat a repo-wide `--check` as a gate. It fails on
   **201 files** (119 `.js`, 44 `.jsx`, 20 `.md`, 12 `.html`, 4 `.json`, 1 `.css`) and always has —
   prettier has never been enforced here, only `eslint-config-prettier` to stop the two fighting. A
   mass reformat is *safe* (deterministic formatter, so the byte-identical ports stay byte-identical
   and the 6 parity tests would catch it if not) but it is a decision, not hygiene: it belongs in its
   own commit on `main` with the SHA recorded in `.git-blame-ignore-revs`, never mixed into a sweep.
   **Settled — do not re-litigate this each run.**
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
  was checked clean. The audit ledgers are out of tree; if `reports/` reappears, flag it.
