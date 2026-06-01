# kunji node demo — "Sign in with kunji" with no Firebase, no framework

A complete relying party in **plain Node** (`http`) with an **in-memory** session store and a
single dependency (`@noble/curves`, for Ed25519 verification). It proves the point: kunji runs **no
backend in the login path** and shares **no database** with your app — _any_ server works. The
wallet POSTs a signed assertion straight to your callback; you verify it and you're done.

Prefer Firebase? See [`../kunji-login-demo`](../kunji-login-demo). Want to keep the server local but
still test with a real phone (no tunnel)? See [`../kunji-relay-demo`](../kunji-relay-demo). The
protocol is identical across all three — only the storage/host differ.

## Run it

```bash
npm install
npm start                 # → http://localhost:3000
```

Open it and you'll see the official **Sign in with kunji** button (the drop-in `rp.js` widget).

The server binds **all interfaces** (`0.0.0.0`) by default, so it's already reachable on your
machine's LAN IP — not just `localhost`.

## Reaching it from another device (LAN IP) — and the HTTPS catch

Find your IP and open it from any device on the same network:

```bash
# macOS:    ipconfig getifaddr en0
# Linux:    hostname -I        # first address
# Windows:  ipconfig           # IPv4 Address
# → e.g. open  http://192.168.1.50:3000   (restrict the bind with  HOST=127.0.0.1 npm start)
```

Over a LAN IP, the **wallet simulator works as-is** (it doesn't require TLS):

```bash
BASE=http://192.168.1.50:3000 npm run wallet
```

But a **real kunji wallet (your phone, app.kunji.cc) will refuse an `http://<ip>` callback.** The
wallet requires **HTTPS** for any host that isn't `localhost`/`127.0.0.1` — a deliberate anti-MITM
rule, so a bare LAN IP over http can't complete a real sign-in. For real-wallet testing you need a
public **HTTPS** URL:

```bash
cloudflared tunnel --url http://localhost:3000      # → https://something.trycloudflare.com
# or: ngrok http 3000
```

Open the tunnel's HTTPS URL on your phone. The server reads `x-forwarded-proto`/`x-forwarded-host`,
so it derives the correct `https://…` audience + callback automatically. Behind a proxy that doesn't
set those, pin it explicitly: `PUBLIC_ORIGIN=https://demo.example.com npm start`.

> TL;DR — **LAN IP + simulator:** works over http. **LAN IP + real phone wallet:** needs HTTPS (use
> a tunnel). `localhost` is the only http host the wallet trusts, and a phone can't reach your
> `localhost`.

## Serving HTTPS yourself (certificates)

The server serves HTTPS when you give it a key + cert — but you must **generate them first** (the
`TLS_KEY`/`TLS_CERT` vars just point at existing files):

```bash
# Option A — device-trusted, works with a real wallet (replace the IP with yours):
mkcert -cert-file cert.pem -key-file key.pem 192.168.1.50 localhost
# Option B — self-signed, simulator only (a real phone wallet will reject it):
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -keyout key.pem -out cert.pem \
  -subj "/CN=localhost" -addext "subjectAltName=IP:192.168.1.50,DNS:localhost"

# then start over HTTPS:
TLS_KEY=./key.pem TLS_CERT=./cert.pem PORT=8443 npm start
```

**The catch with a self-signed cert:** it will _not_ work with a real wallet. The wallet runs in a
browser (app.kunji.cc) and `fetch()`es your callback — browsers hard-reject untrusted certs with no
programmatic override, and public CAs (Let's Encrypt) don't issue for bare LAN IPs. The cert must be
**trusted by the connecting device.** Two ways that actually work:

- **[mkcert](https://github.com/FiloSottile/mkcert) on your LAN** — a real phone scanning the QR,
  no tunnel. See the recipe just below.
- **A tunnel** (simplest, no cert wrangling) — `cloudflared tunnel --url http://localhost:3000`
  gives a publicly-trusted HTTPS URL that works on any device, no CA install.

### Real phone over your LAN, no tunnel (mkcert)

1. **Make a local CA + a cert for your LAN IP** (replace the IP with yours):
   ```bash
   mkcert -install                                   # creates a local CA on your laptop
   mkcert -cert-file cert.pem -key-file key.pem 192.168.1.50 localhost
   TLS_KEY=./key.pem TLS_CERT=./cert.pem PORT=8443 npm start
   ```
2. **Trust that CA on the phone** — the step everyone misses. Copy `rootCA.pem` from
   `$(mkcert -CAROOT)` to the phone (AirDrop / email / download) and install it:
   - **iOS:** open it → Settings → _Profile Downloaded_ → Install. Then **mandatory**: Settings →
     General → About → _Certificate Trust Settings_ → enable full trust for the mkcert CA.
   - **Android:** Settings → Security → _Encryption & credentials_ → _Install a certificate_ → _CA
     certificate_ → pick `rootCA.pem`.
3. **Same Wi-Fi, reachable:** phone + laptop on the same network with **no AP/client isolation**
   (common on guest Wi-Fi), and the laptop firewall must allow inbound on the port (e.g. 8443).
   Sanity check: open `https://192.168.1.50:8443` on the phone — it should load with no warning.
4. **Sign in:** open the demo on your laptop, _Sign in with kunji_, and **scan the QR with the kunji
   app on the phone**. The wallet POSTs to `https://192.168.1.50:8443/kunji/callback` over trusted
   HTTPS; the server already returns the **Private Network Access** header so Chrome doesn't block
   the public→private request.

Cert warning on the phone → the CA isn't trusted (redo step 2; on iOS the trust toggle is required).
Request hangs → it's almost always AP isolation or the laptop firewall (step 3).

The **simulator** accepts self-signed/mkcert certs automatically (it's a test tool):
`BASE=https://192.168.1.50:8443 npm run wallet`.

> Two more things the demo already handles for real-wallet use: the callback sends **CORS** headers
> (the wallet POSTs cross-origin), and the scheme is derived from the TLS socket / `x-forwarded-proto`
> so the signed `audience` + `callbackUrl` come out as `https://…`.

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
