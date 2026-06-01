# kunji self-hosted demo — own Firebase, on-prem worker, dynamic IP, no tunnel

A **production-shaped**, self-hosted "Sign in with kunji" relying party. Your **own** Firebase
project is the public front door (Hosting + a custom domain + Auth custom tokens + Firestore
accounts); the part you keep on your own hardware is a **worker on a dynamic IP** that reacts to
logins. Dynamic IP is a non-issue — Firebase has the stable public URL, and your box only connects
**outbound**, so there's no DDNS, no port-forward, no tunnel.

This is the production sibling of [`../kunji-relay-demo`](../kunji-relay-demo) (a test harness). The
difference that matters: here the callback is behind **your custom domain**, so the per-app `sub` is
your **real production identity**, and the user gets a genuine **Firebase auth session**.

```
phone wallet ─POST assertion─► https://app.YOURDOMAIN.com/kunji/callback   (Hosting → Function)
users' browsers ─► Firebase Hosting (frontend) + Firestore + Auth           │ verify §6, upsert
                                                                             ▼ users/{sub}, mint token
                                                          Firestore / Auth (YOUR project)
                                                                             ▲ onSnapshot (outbound)
                          your dynamic-IP box ── worker.js ──────────────────┘  (private logic; no inbound)
```

## Pieces

| File | Where it runs | Role |
| --- | --- | --- |
| `functions/index.js` | Firebase (public) | `createSession`, `kunjiCallback` (verify §6 → upsert `users/{sub}` → mint **custom token** §7 → approve), `getSessionStatus` |
| `functions/verify.js` | Firebase | the §6 verifier (shared with the simulator) |
| `public/index.html` | Firebase Hosting | widget → `signInWithCustomToken` → reads `users/{sub}` |
| `firestore.rules` | Firebase | `users/{sub}` readable/writable only when `request.auth.uid == sub` |
| `worker.js` | **your box (dynamic IP)** | outbound Firestore listener; runs your private on-prem logic |
| `wallet-sim.js` | anywhere | no-phone end-to-end test against the deployed endpoints |

## One-time setup (your Firebase project, Blaze plan)

```bash
cd functions && npm install && cd ..

# Deploy the front door (functions + hosting + locked rules):
firebase deploy --only "functions:selfhosted,hosting,firestore:rules" --project YOUR_PROJECT

# Custom domain (recommended) — gives the REAL production sub:
#   Firebase console → Hosting → Add custom domain → app.yourdomain.com → follow DNS steps.
#   Without it, audience = your-proj.web.app (still works, but that's the identity users get).

# Service account for the local worker:
#   console → Project settings → Service accounts → Generate new private key
#   → save as ./serviceAccount.json   (git-ignored)

# (optional) add a Firestore TTL policy on loginSessions.ttl so sessions self-delete.
```

## Run the on-prem worker (your dynamic-IP box)

```bash
npm install
GOOGLE_APPLICATION_CREDENTIALS=./serviceAccount.json npm run worker
```

It listens outbound and prints `✔ login: sub=…` whenever someone signs in — that's where your
private business logic goes. Reboot, change ISP, swap networks: it just reconnects and **catches up**
on anything it missed (the listener replays all users; `workerSeenAt` keeps the reaction idempotent).

## Test without a phone

```bash
BASE=https://your-proj.web.app npm run wallet            # and: -- --claims
```

Expect `callback: { status: 'ok' }`, then `status: approved` with `sub`, optional `claims`, and
`customToken: ✔ minted`. Then a **real phone**: open your Hosting URL, scan the QR — the browser
`signInWithCustomToken`s and renders `users/{sub}`, and your worker logs the reaction.

## When this is the right shape

You want a real, self-hosted RP but won't expose a home/office server to the internet and your IP is
dynamic. Firebase carries the public login + accounts + auth; your box stays private and reactive. If
users must connect **directly** to your box (large media, LAN devices), that part needs inbound
reachability (DDNS + port-forward) — but the kunji login still flows through Firebase regardless.

## Caveats

- **Blaze plan** (2nd-gen Functions + outbound). Custom-domain DNS is a one-time step.
- **Guard the service-account key** — it's full project access; scope/rotate it, keep it off Git.
- **The worker must be online to react.** Logins still succeed while it's down (Firebase handles
  them); queued reactions run on restart via the catch-up logic above.

Test harness (minimal Firebase): [`../kunji-relay-demo`](../kunji-relay-demo). No Firebase at all:
[`../kunji-node-demo`](../kunji-node-demo). Protocol: [`../../docs/discoverable-login.md`](../../docs/discoverable-login.md)
