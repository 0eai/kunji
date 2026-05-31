---
name: release
description: Cut a kunji release — verify, build, version, tag, deploy, and smoke-test as one ordered procedure. Use when the user wants to ship a versioned release of the app (not a one-off hotfix deploy; for plain deploys use the deploy skill).
---

# Release kunji

An ordered checklist so a release can't skip verification or ship the wrong artifact. Defer to the
`deploy` skill for the Firebase mechanics; this wraps it with versioning and gating.

## Steps

1. **Clean tree.** `git status` — commit or stash unrelated work first. Never release with
   `reports/` staged (it's git-ignored; if it shows up, something is wrong).
2. **Gate.** `npm run lint && npm test && npm run build` — all green. This is identical to CI; if CI
   is red, do not release.
3. **Version bump.** Update `version` in `package.json` (semver). Patch for fixes, minor for
   features, major only for a breaking change to the **login protocol or crypto derivation**
   (those are user-facing wire/identity contracts — see AGENTS.md invariants).
4. **Changelog / notes.** Summarize what changed, especially anything touching `src/lib/crypto/`,
   `functions/`, `firestore.rules`, or the assertion format — those carry compatibility risk.
5. **Commit + tag.**
   ```bash
   git commit -am "release: vX.Y.Z"
   git tag vX.Y.Z
   ```
   (Commit message ends with the `Co-Authored-By` trailer.)
6. **Deploy.** Use the `deploy` skill. Typically `hosting:app`; add `functions:app` /
   `firestore:rules` only if those changed. Consider a **preview channel** first for anything
   risky: `firebase hosting:channel:deploy rel-X-Y-Z --only app`.
7. **Smoke test live** (the `deploy` skill's checklist) on app.kunji.cc.
8. **Publish.** `git push && git push --tags` — **the user must run this**; no git remote is
   configured in the agent environment.

## Don't

- Don't bump major for an internal refactor — major is reserved for protocol/crypto breaks.
- Don't release the `landing` site or `rp.js` unless they actually changed (see deploy skill).
- Don't tag before the gate passes.
