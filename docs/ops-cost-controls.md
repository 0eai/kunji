# Cost controls — Cloud Functions abuse / runaway-spend

kunji's public functions are unauthenticated (`onRequest`) and reached over HTTPS, so they're an
open cost surface. Two layers bound the spend.

## 1. Per-function instance caps (in code — already applied)

Every 2nd-gen function sets `maxInstances` so a flood can't scale compute without bound. The cap ×
the (default 80) concurrency is the hard ceiling on simultaneous work; scale-to-zero is kept (no
`minInstances`, no idle cost).

| Function | codebase | maxInstances |
|---|---|---|
| `vaultWrite` | `app` (`functions/index.js`) | 10 |
| `linkLookup` | `app` | 5 |
| `agentCapabilityPoll` | `app` | 5 |
| `agentRequestRelay` | `app` | 5 |
| `credentialPoll` | `app` | 5 |
| `credentialOfferRelay` | `app` | 5 |
| `pushDispatch` | `app` | 5 |
| demo `createSession` / `lookupSession` / `getSessionStatus` / `kunjiCallback` / `kunjiAgent` | demo codebases | 5 |

To change a cap, edit the `onRequest({ …, maxInstances: N })` option and redeploy that function with
an explicit `--only` (see the `deploy` skill — never a bare `firebase deploy`).

`linkLookup` also validates the `^\d{8}$` code format **before** its Firestore-backed rate limiter,
so malformed spam can't generate rate-limit writes. The agent relays are per-IP rate-limited the
same way — `agentCapabilityPoll` at 60/min (a human-in-the-loop poll across the approval window) and
`agentRequestRelay` at 20–30/min — and reject malformed input before the limiter.

`pushDispatch` (the opt-in Web Push relay, push-relay.md Transport ②) validates the request shape
**before** the limiter, then rate-limits **per-IP** (20/min) and, after proving holder-of-key against the
channel's registered key, **per-channel** (10/min, keyed by `channelId`) — so neither anonymous spam nor a
single authorized poster can flood a wallet with notifications. The Web Push payload is the opaque pointer
only (`{requestId}`), E2E-encrypted by `web-push` to the subscription.

## VAPID keys for the push relay (one-time, manual)

`pushDispatch` signs Web Push with a VAPID keypair. Generate once and store as Functions secrets:

```bash
npx web-push generate-vapid-keys                      # prints a Public Key + Private Key
firebase functions:secrets:set VAPID_PUBLIC_KEY        # paste the Public Key
firebase functions:secrets:set VAPID_PRIVATE_KEY       # paste the Private Key
# optionally pin the contact subject (defaults to mailto:security@kunji.cc):
#   set VAPID_SUBJECT in the function env
```

Ship the **public** key to the wallet build as `VITE_VAPID_PUBLIC_KEY` (it's public — used by
`pushManager.subscribe`). Rotating the private key invalidates existing subscriptions (wallets re-subscribe).

## 2. Cloud Billing budget + alert (project-wide backstop — manual, one-time)

`maxInstances` caps each function; a billing budget bounds *total* project spend (functions +
Hosting + Firestore) regardless of attack vector. Create one on the `kunji-cc` billing account with
threshold alerts. Requires the billing-account id (`gcloud billing accounts list`) and the
`billing.budgets.create` permission (Billing Account Administrator).

```bash
# Find the billing account id (form: XXXXXX-XXXXXX-XXXXXX)
gcloud billing accounts list

# Create a monthly budget scoped to kunji-cc with 50/90/100% email alerts to billing admins.
gcloud billing budgets create \
  --billing-account=<BILLING_ACCOUNT_ID> \
  --display-name="kunji-cc monthly" \
  --filter-projects="projects/kunji-cc" \
  --budget-amount=<e.g. 50USD> \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0
```

This is **alert-only** — it notifies, it does not stop spend.

## 3. (Optional, opt-in) break-glass kill-switch — NOT enabled by default

A budget can publish to a Pub/Sub topic; a function subscribed to it can call the Cloud Billing API
to **disable billing** at ≥100%. ⚠️ Disabling billing takes the **entire** `kunji-cc` project
offline — app.kunji.cc, Firestore, the wallet — i.e. it trades a cost spike for a full outage of an
identity wallet, and the function's service account needs **Billing Account Administrator**. Default
to alert-only; only wire this up as a conscious "rather go dark than get billed" decision. If built,
put it in its own Functions codebase so it never prunes `app`.

## Deferred
Firebase App Check enforcement on `vaultWrite`/`linkLookup` (stronger bot defense; changes the
write-path + needs reCAPTCHA Enterprise + carries lockout risk) is intentionally **not** done yet —
see `docs/agentic-delegation.md` (agent traffic revisits this).
