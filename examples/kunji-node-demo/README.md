# kunji node demo — "Sign in with kunji" with no Firebase, no framework

A complete relying party in **plain Node** (`http`) with an **in-memory** session store and a
single dependency (`@noble/curves`, for Ed25519 verification). It proves the point: kunji runs **no
backend in the login path** and shares **no database** with your app — _any_ server works. The
wallet POSTs a signed assertion straight to your callback; you verify it and you're done.

Prefer Firebase? See [`../kunji-login-demo`](../kunji-login-demo). The protocol is identical — only
the storage/host differ.

## Run it

```bash
npm install
npm start                 # → http://localhost:3000
```

Open it and you'll see the official **Sign in with kunji** button (the drop-in `rp.js` widget).

> ⚠️ A real wallet (your phone, or app.kunji.cc) must reach your `callbackUrl` over **HTTPS**, so a
> phone can't talk to `localhost`. To test with a real wallet, deploy this anywhere with a public
> HTTPS URL, or expose it with a tunnel (e.g. `cloudflared tunnel --url http://localhost:3000`) and
> open the tunnel URL. The server derives its `audience`/`callbackUrl` from the request host (honors
> `x-forwarded-*`), so it just works behind a tunnel.

## Test the whole flow locally — no phone needed

`wallet-sim.js` does what the wallet does on the signing side (derive an Ed25519 key, build the
assertion, sign it over canonical JSON, POST it to the callback), then polls for approval:

```bash
npm run wallet            # default pseudonymous identity
npm run wallet -- --claims   # also share a (fake) self-asserted profile
```

You'll see the session approved, the `sub`, the derived default identity (e.g. _"Wandering Fox 42"_),
and the shared `claims` when present.

## What's where

| File              | Role                                                                       |
| ----------------- | -------------------------------------------------------------------------- |
| `server.js`       | Node `http` server: `/api/session`, `/kunji/callback`, `/kunji/status`     |
| `verify.js`       | The spec §6 verifier — pure, no I/O, no Firebase (`node:crypto` + `@noble`) |
| `public/index.html` | Frontend using the `rp.js` widget + `kunji.handle(sub)` for the identity |
| `wallet-sim.js`   | A simulated wallet so you can run the full flow without a device           |

## Showing the user

You receive a stable, anonymous `sub` — **not** a verified name/email/photo. **kunji authenticates;
your app owns the profile.**

- **Default identity:** `kunji.handle(sub)` (shipped in `rp.js`) gives a friendly name + identicon
  derived from `sub` — distinct per app, stable, unlinkable. No blank avatars, no extra call.
- **Custom profile (optional):** request it with `scope: 'profile'`. If the user consents, the
  assertion carries `claims` (`{ name, picture }`). It's signed (tamper-evident) but **self-asserted
  and never verified** — HTML-escape the name, render the picture client-side only (never
  server-fetch it), and never use claims for authorization. Store your profile keyed by `sub`.

## Going to production

- **Hardcode/derive your `audience` + `callbackUrl` server-side** and verify against them (done here
  via the request host); never trust client-supplied values.
- Swap the in-memory `Map` for your real store (Postgres, Redis, …) and key users by `sub`.
- Verify **all** of §6 (this reuses `verifyAssertion`) and consume each session **once**.

Full protocol: [`../../docs/discoverable-login.md`](../../docs/discoverable-login.md)
