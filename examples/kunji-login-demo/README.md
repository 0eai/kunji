# kunji Login Demo

A minimal **reference relying party** showing how a web app adds passwordless
"Sign in with kunji" using the **v2 discoverable** flow.

The user opens this login page, scans the QR with the kunji app, taps **Approve**,
and is signed in — no password, no email link, no Google. Kunji shares **no database**
with this app: the only thing that crosses the boundary is a signed assertion POSTed
to this app's own callback endpoint.

```
 login page ──── QR (sessionId, challenge, audience, callbackUrl) ───►  kunji wallet
                                                                          │ approve
 dashboard ◄── poll /api/session ◄── verify §6 ◄── POST /kunji/callback ──┘
```

## Architecture

Unlike a federated IdP, the app trusts whatever public key the wallet presents and
verifies a signature over a fresh challenge (the SSH / Nostr / passkey model). First
key seen → new user; returning key → existing user.

- **`server/index.js`** — tiny Express backend (in-memory sessions, no DB):
  - `POST /api/session` — create a session (`challenge`, `expiresAt`).
  - `POST /kunji/callback` — receive the wallet's signed assertion, run full verification.
  - `GET /api/session/:id` — the frontend polls this for the result.
- **`server/verify.js`** — the §6 verification: signature (Ed25519 over canonical JSON),
  `sub === SHA-256(publicKey)`, challenge/audience match, freshness, single-use.
- **`src/LoginPage.jsx`** — creates a session, renders the v2 QR, polls for the result.
- **`src/Dashboard.jsx`** — shows the verified `sub`.

## Run

```bash
npm install
npm run dev      # starts the Express backend (:8787) + Vite (:5173) together
```

Open http://localhost:5173, then scan the QR with the kunji app
(`app.kunji.cc`, or your local kunji dev build). Tap **Approve**.

> Note: for a quick same-machine test, the wallet must be able to reach
> `http://localhost:5173/kunji/callback`. On a phone, point the wallet at a publicly
> reachable deployment of this demo instead.

## The signed assertion (what the wallet POSTs)

```json
{
  "publicKey": "<base64 Ed25519 public key>",
  "signedPayload": { "sessionId": "...", "challenge": "...", "audience": "localhost", "sub": "<hex>", "timestamp": 0 },
  "signedToken": "<base64 Ed25519 signature over canonical-JSON(signedPayload)>"
}
```

## Going to production

- **Hardcode your domain** as the `audience` server-side (this demo accepts it from the
  client for convenience). Verify `signedPayload.audience === yourDomain`.
- Serve the callback over **HTTPS** on your real domain (the wallet requires
  HTTPS + same-site callback; HTTP is allowed only for `localhost`).
- Replace the in-memory session map with your own store, and replace the demo
  "signed in" state with your real session / a Firebase custom token
  (see the kunji spec §7 for the custom-token bridge).

Full protocol: [`../../docs/discoverable-login.md`](../../docs/discoverable-login.md)
