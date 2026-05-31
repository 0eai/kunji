---
name: deploy
description: Deploy kunji to Firebase Hosting/Functions/Firestore. Use when shipping the app, landing site, widget, the vaultWrite function, or Firestore rules. Encodes the multi-site + single-codebase topology and the post-deploy smoke checklist so the wrong target isn't shipped and live functions aren't pruned.
---

# Deploy kunji

Firebase project **`kunji-cc`**. Always deploy with an **explicit `--only` target** — never a bare
`firebase deploy` (it touches everything, including things you didn't build).

## Topology (from `firebase.json` + `.firebaserc`)

| Target | Site | URL | Source |
|---|---|---|---|
| `hosting:app` | `app-kunji-cc` | app.kunji.cc | `dist/` (Vite build) |
| `hosting:landing` | `kunji-cc` | kunji.cc | `landing/` |
| `hosting:redirect` | `kunji-xyz` | (301 → kunji.cc) | `redirect-xyz/` |
| `functions:app` | — | `/vault/write` rewrite | `functions/` (codebase `app`, Node 20, us-central1) |
| `firestore:rules` | — | — | `firestore.rules` |

The **demo** (`examples/kunji-login-demo/`) is a **separate Firebase project** with its own
`.firebaserc`. It is NEVER deployed from here — `cd` into it and deploy on its own config.

## Pre-flight (always)

```bash
npm run lint && npm test && npm run build
```
All three must be green. `npm run build` writes `dist/`, which is what `hosting:app` serves.

## Common deploys

- **App (most common):** `npm run build && firebase deploy --only hosting:app`
- **Landing site:** `firebase deploy --only hosting:landing`
- **vaultWrite function:** `firebase deploy --only functions:app`
  (or `--only functions:app:vaultWrite` for the single function)
- **Firestore rules:** `firebase deploy --only firestore:rules`
- **Preview channel (no live impact):** `firebase hosting:channel:deploy <name> --only app`

## The widget (`rp.js`)

`rp.js` source is in `widget/`; it's built with esbuild into `landing/rp.js` (committed) and served
from kunji.cc/rp.js. **If a change only reformatted code, the minified `rp.js` is byte-identical** —
re-verify the hash is unchanged and skip the `landing` redeploy. Only redeploy `landing` when
`rp.js` or the site's HTML actually changed.

## Gotchas

- **One codebase, but stay explicit.** Functions live in a single codebase `app`. Deploying
  `--only functions` only affects codebase `app` here, but use `--only functions:app` to make
  intent unmistakable and avoid surprises if more codebases are ever added.
- **HTML is served `no-cache`; `/assets/**` is immutable.** A hosting:app deploy is effectively
  atomic for users — new HTML points at new hashed assets. No SW cache-busting needed.
- **Don't deploy `firestore:rules` casually** — the rules are the only thing stopping direct client
  vault writes (`write: if false`). Re-read `firestore.rules` and confirm the deny-by-default
  posture before shipping rule changes.

## Post-deploy smoke (app)

On app.kunji.cc: unlock vault → open QR scanner (lazy chunk + camera) → link-device screen →
register + remove an app (exercises the `vaultWrite` path) → theme toggle Light/Dark/System.
If functions changed, confirm a vault write succeeds (not `vault_write_failed`).
