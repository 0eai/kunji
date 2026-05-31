# kunji Login Demo

A minimal **reference relying party** showing how a web app adds passwordless
"Sign in with kunji" using the **v2 discoverable** flow.

The user opens this login page, scans the QR with the kunji app, taps **Approve**,
and is signed in — no password, no email link, no Google. Kunji shares **no database**
with this app: the only thing that crosses the boundary is a signed assertion POSTed
to this app's own callback.

```
 login page ──── QR (sessionId, challenge, audience, callbackUrl) ───►  kunji wallet
                                                                          │ approve
 dashboard ◄── onSnapshot(loginSessions) ◄── verify §6 ◄── POST /kunji/callback ──┘
```

## Architecture

The app trusts whatever public key the wallet presents and verifies a signature over a
fresh challenge (the SSH / Nostr / passkey model). First key seen → new user; returning
key → existing user.

- **`functions/index.js`** — Firebase **Cloud Functions** (the RP's own backend):
  - `createSession` (served at `/api/session` via Hosting rewrite) — writes
    `loginSessions/{id}` (status `pending`) to Firestore.
  - `kunjiCallback` (served at `/kunji/callback`, **same-site** so the wallet accepts it)
    — receives the signed assertion and runs the full §6 verification, then marks the
    session `approved` + stores the `sub`.
- **`functions/verify.js`** — §6 verification: Ed25519 signature over canonical JSON,
  `sub === SHA-256(publicKey)`, challenge/audience match, freshness, single-use.
- **`src/LoginPage.jsx`** — creates a session, renders the v2 QR, and uses Firestore
  **`onSnapshot`** on its session doc → flips to "signed in" the instant the wallet approves.

Sessions live in **Firestore** (not in memory), so the flow is correct across Cloud
Functions instances. For demo simplicity the Functions/Firestore live in the **kunji-cc**
project — _a production RP would use its own project and hardcode its own domain as the
audience server-side._

## Deploy

Requires the Firebase **Blaze** plan (Cloud Functions). From this directory:

```bash
npm install
cp .env.example .env      # fill in the kunji-cc web config (same values as the kunji app)
(cd functions && npm install)
npm run deploy            # vite build + firebase deploy (functions + hosting:kunji-demo)
```

Then open the deployed site (e.g. `https://kunji-demo.web.app`) and scan the QR with the
kunji app. Tap **Approve** → the page signs you in and shows your `sub`.

> The callback must be publicly reachable by the phone, which is why this uses deployed
> Functions rather than `localhost`/a tunnel. `npm run dev` runs the frontend only.

## The signed assertion (what the wallet POSTs)

```json
{
  "publicKey": "<base64 Ed25519 public key>",
  "signedPayload": {
    "sessionId": "...",
    "challenge": "...",
    "audience": "kunji-demo.web.app",
    "sub": "<hex>",
    "timestamp": 0,
    "claims": { "name": "Ada Lovelace", "picture": "data:…" }
  },
  "signedToken": "<base64 Ed25519 signature over canonical-JSON(signedPayload)>"
}
```

## Showing the user (default identity + claims)

This demo requests `scope: ['profile']`, so the wallet offers to share a custom name/photo. After
verification the demo renders the resolved identity (`src/Dashboard.jsx`):

- **`claims` present** (user consented) → show `claims.name` / `claims.picture`. These are signed but
  **self-asserted and unverified** — the demo treats them as untrusted (React escapes the name; the
  picture is an `<img>`, never server-fetched).
- **no `claims`** → fall back to the deterministic default identity from `sub` via
  `deriveHandle(sub)` (`src/lib/kunjiHandle.js`) — a friendly name + kunji identicon, stable and
  unlinkable. A third-party RP would use `kunji.handle(sub)` from `rp.js` instead.

## Going to production

- **Hardcode your domain** as the `audience` server-side and verify it in `kunjiCallback`.
- Use your **own** Firebase project (its own Firestore + Functions).
- Replace the demo "signed in" state with your real session / a Firebase custom token
  (see the kunji spec §7 for the custom-token bridge).

Full protocol: [`../../docs/discoverable-login.md`](../../docs/discoverable-login.md)
