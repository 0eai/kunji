# kunji relay demo — local RP, real phone, no tunnel

Run your relying party **locally** (dynamic IP, behind NAT) and still sign in from a **real phone**,
with **no tunnel** and no LAN certificates. The trick: don't make the phone reach your laptop — have
both connect _outbound_ to Firebase and meet there. Only a thin **callback Function** is public; your
actual RP runs on your machine.

```
phone wallet (app.kunji.cc) ──POST assertion──► kunjiCallback Function ──► Firestore
                                                  (public HTTPS, verifies §6)    │
laptop browser ──/api/session,/kunji/status──► LOCAL RP server ◄── onSnapshot ───┘
                                               (creates sessions, your business logic; outbound only)
```

Because the laptop only makes **outbound** connections to Firebase, its IP is never needed — dynamic
IP, NAT, changing networks, all irrelevant. No tunnel, no port-forward, no cert install.

## Why "verify-in-Function" (and not the alternatives)

| Approach | Security | Cost | |
| --- | --- | --- | --- |
| **Verify-in-Function** (this demo) | **Best** — the §6 signature/challenge/audience/freshness checks run at the public edge; bad assertions are rejected before anything is stored or relayed. Firestore stays **deny-all**. | ~1 Function call per login (free tier). | ✅ |
| Relay-raw, verify locally | Middle — unverified data lands in your DB + laptop first (spam/DoS surface). | same | |
| RTDB REST URL (no Function) | **Worst** — needs open DB write rules for the anonymous wallet; no edge validation; abuse can drain quota. | "cheapest" until abused | ✗ |

So this demo verifies at the edge; your **local** server still owns sessions and all business logic.

## One-time setup

You need a Firebase project on the **Blaze** plan (2nd-gen Functions). Then:

```bash
# 1. Deploy the public callback Function + locked Firestore rules
cd functions && npm install && cd ..
firebase deploy --only "functions:relay,firestore:rules" --project YOUR_PROJECT
#   → note the printed callback URL, e.g. https://kunjicallback-xxxx-uc.a.run.app

# 2. A service-account key so the LOCAL server can talk to Firestore (outbound).
#    Firebase console → Project settings → Service accounts → Generate new private key
#    → save as ./serviceAccount.json  (git-ignored)

# 3. (optional) add a Firestore TTL policy on the `ttl` field of `relaySessions`
#    so expired sessions auto-delete.
```

## Run

```bash
npm install
RELAY_CALLBACK_URL=https://kunjicallback-xxxx-uc.a.run.app \
GOOGLE_APPLICATION_CREDENTIALS=./serviceAccount.json \
npm start                                   # → http://localhost:3000
```

**Test the whole relay with no phone:**

```bash
npm run wallet            # and: npm run wallet -- --claims
```

It signs a real assertion, POSTs it to the **public** Function, and watches your **local** status flip
to `approved` — proving the round-trip through Firebase to your laptop.

**Real phone (no tunnel):** open `http://localhost:3000` on your laptop, click _Sign in with kunji_,
and scan the QR with the kunji app. The wallet POSTs to the public Function (works on any network);
your local server's listener sees the approval. Watch the server log print `✔ … approved · sub=…`.

## Files

| File | Role |
| --- | --- |
| `functions/index.js` | Public `kunjiCallback` — verifies §6 at the edge, writes the result to Firestore |
| `functions/verify.js` | The §6 verifier (shared with the local server + simulator — no drift) |
| `firestore.rules` | `deny-all` — only the Admin SDK (Function + local server) touches data |
| `server.js` | Local RP — creates sessions, listens via `onSnapshot`, runs your business logic |
| `public/index.html` | Frontend: pulls `/config`, renders the widget, shows the resolved identity |
| `wallet-sim.js` | Full end-to-end test with no phone |

## The one real caveat

The wallet requires `callbackUrl` to be **same-site as `audience`**, and the callback lives on the
**Firebase** domain — so during relay testing the per-app **`sub` is derived from that Firebase
domain, not your production audience**. Perfect for testing the flow, the approval UX, claims, and
your business logic; it is **not** the `sub` your users will have in production. The only way to get
the production `sub` is to host the callback on your real domain (i.e. a deploy). Everything else here
is faithful.

Firebase-free variant: [`../kunji-node-demo`](../kunji-node-demo). Firebase end-to-end (hosted):
[`../kunji-login-demo`](../kunji-login-demo). Production self-hosted (own Firebase + on-prem worker):
[`../kunji-selfhosted-demo`](../kunji-selfhosted-demo). Protocol:
[`../../docs/discoverable-login.md`](../../docs/discoverable-login.md)
