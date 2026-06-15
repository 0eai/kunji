# kunji

**Be your own key.**

A zero-knowledge identity wallet. Your keys, your apps — no Google, no passwords, no tracking.

kunji lets you sign in to apps by scanning a code, authenticated by keys that never leave your device. Each app sees a different, unlinkable identity, and there's no account to create and no company in the middle.

- **App:** https://app.kunji.cc
- **Site:** https://kunji.cc · **Security:** https://kunji.cc/security · **Developers:** https://kunji.cc/developers
- **Live demos:** https://demo.kunji.cc (sign-in · verified credentials · agent authorization · the drop-in widget)

---

## The three pillars

- **Zero-knowledge.** Your vault is encrypted on-device with a key derived from your passphrase (Argon2id → AES-GCM master key). The servers store only ciphertext; sign-in is anonymous (no email/phone/name).
- **Per-app identity.** A deterministic per-domain Ed25519 keypair is derived from your master key; an app only ever sees `sub = hex(SHA-256(utf8(publicKeyBase64)))`. Different domain → unrelated key, so apps can't correlate you.
- **Self-sovereign.** No registry, no gatekeeper. Your vault syncs across your devices via a master-key-derived id; a recovery key restores everything. Lose your vault _and_ recovery key and no one — including us — can restore it. That's the trade-off for nobody being able to lock you out.

The plain-language + verifiable version of all this lives at **[kunji.cc/security](https://kunji.cc/security)**, with links to the exact source.

## "Sign in with kunji" (for app developers)

kunji shares **no database** with your app and runs **no backend in the login path**. You create a session, show a QR / 6-digit code, and verify a signed assertion the wallet POSTs straight to your own callback.

**kunji authenticates; your app owns the profile.** You get a stable, anonymous per-app `sub` — not a verified name/email/photo. To avoid blank avatars, every `sub` maps to a friendly default name + identicon via `kunji.handle(sub)`; the user can optionally share a custom (self-asserted, unverified) profile per app. See [§8 of the protocol doc](docs/discoverable-login.md).

Fastest path — the drop-in widget:

```html
<script src="https://kunji.cc/rp.js"></script>
<div
  data-kunji-signin
  data-app-name="Your App"
  data-audience="yourapp.com"
  data-session-url="/kunji/session"
  data-callback-url="/kunji/callback"
  data-poll-url="/kunji/status"
  data-redirect="/dashboard"
></div>
```

- **Protocol & message formats:** [`docs/discoverable-login.md`](docs/discoverable-login.md)
- **Guides:** [kunji.cc/developers](https://kunji.cc/developers) · [Firebase end-to-end](https://kunji.cc/developers/firebase) · [try it live](https://demo.kunji.cc/#rpjs)
- **Working reference RPs:** [`examples/kunji-login-demo/`](examples/kunji-login-demo) (Firebase) · [`examples/kunji-node-demo/`](examples/kunji-node-demo) (plain Node — no Firebase, no framework) · [`examples/kunji-agent-demo/`](examples/kunji-agent-demo) (plain Node + agent logins — `POST /kunji/agent`) · [`examples/kunji-relay-demo/`](examples/kunji-relay-demo) (local server + Firebase relay — real phone, no tunnel) · [`examples/kunji-selfhosted-demo/`](examples/kunji-selfhosted-demo) (own Firebase + on-prem worker on a dynamic IP)

### Let an agent sign in for you

Beyond human login, kunji supports **agentic delegation**: a user authorizes an agent (an AI assistant, script, or service) to act for them at one app via a **scoped, expiring, revocable, holder-of-key capability** — the agent never receives the user's keys. See [`docs/agentic-delegation.md`](docs/agentic-delegation.md) and the [agents demo](https://demo.kunji.cc/#agentic). Run it end-to-end with [`examples/kunji-agent-demo/`](examples/kunji-agent-demo) (the RP) + [`examples/kunji-mcp/`](examples/kunji-mcp) (the MCP bridge for AI runtimes).

## Repository layout

```
src/                     the kunji PWA — React 19 + Vite + Tailwind v4
  components/            UI (LockScreen, Dashboard, Approval/Details sheets, ui/ primitives)
  services/              identity.js, vault.js, linking.js, activityLog.js
  lib/crypto/            Argon2id, AES-GCM, Ed25519, canonical-JSON signer
  lib/theme.js           light / dark / system theme control
landing/                 static marketing site + /developers + /security guides
  rp.js, rp.v1.js        built "Sign in with kunji" widget (source in widget/)
widget/                  widget source; esbuild → landing/rp.js
examples/                 reference relying parties: kunji-login-demo (Firebase), kunji-node-demo
                          (plain Node), kunji-agent-demo (plain Node + agent logins), kunji-relay-demo
                          (local + relay), kunji-selfhosted-demo; kunji-mcp (MCP bridge for AI runtimes)
docs/discoverable-login.md  the v2 discoverable-login protocol
docs/agentic-delegation.md  agentic delegation — capabilities for AI agents
docs/ops-cost-controls.md   Cloud Functions abuse / cost controls
docs/{scope,verified-credentials,push-relay}.md  design (proposed, not yet built)
firestore.rules          Firestore security rules
firebase.json            Hosting: app / landing / redirect targets
```

## Development

Requires Node 20+.

```bash
npm install
cp .env.example .env        # fill in your Firebase web config (VITE_FIREBASE_*)
npm run dev                 # Vite dev server
npm run build               # production build → dist/
npm run lint
```

The app needs a Firebase project with **Anonymous Auth** and **Firestore** enabled; config is read from `VITE_FIREBASE_*` env vars (see `.env.example`).

**Widget** (`widget/`): `npm install && npm run build` → emits `landing/rp.js` + `rp.v1.js`.

**Demo** (`examples/kunji-login-demo/`): its own `npm install` / `.env`, plus Cloud Functions in `functions/`.

## Deployment

Firebase Hosting, multi-site (`.firebaserc` targets):

```bash
npm run build
firebase deploy --only hosting:app        # app.kunji.cc
firebase deploy --only hosting:landing    # kunji.cc (+ /developers, /security)
# hosting:redirect → kunji.xyz 301 → kunji.cc

# preview channel (no production impact):
firebase hosting:channel:deploy <name> --only app,landing
```

## Security model

Keys are generated and used only on-device; only signatures ever leave the vault. The vault is encrypted with an Argon2id-derived key; the server holds ciphertext + salts and an encrypted validator. Per-app keys are derived per domain, so identities are unlinkable across apps. In the cross-app login path kunji is a pure client — scan → sign → POST — and shares no storage with relying parties. Full threat model and rationale: [`docs/discoverable-login.md`](docs/discoverable-login.md) §9 and [kunji.cc/security](https://kunji.cc/security).
