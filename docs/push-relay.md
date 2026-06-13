# kunji step-up authorization & the opt-in push relay — design

**Status:** Design (proposed) — **not implemented.** This covers how an **already-connected** app or
agent can later ask the user for **more scope** ([`scope.md`](./scope.md)) or a **verified
credential** ([`verified-credentials.md`](./verified-credentials.md)), and how the kunji wallet
notifies the user to approve — **without** kunji becoming a user directory. The **push relay is
opt-in and only for the case where the RP has no channel of its own to the user**; the default path
uses no new kunji infrastructure.

## 1. The problem

After a user signs in (or authorizes an agent), the app/agent later needs something more — a broader
scope, or proof of an attribute. We want: *connected app requests → kunji wallet notifies → user
approves the delta → the new capability/credential is delivered*. This is **incremental (step-up)
authorization**.

## 2. The two hard constraints

1. **kunji holds no app↔user directory — by design.** Per-app unlinkability and anonymity mean kunji
   does **not** know which user uses which app. So kunji cannot, on its own, route "example.com wants
   more scope" to a wallet. It doesn't know who that is, and must not.
2. **The wallet has no push today** — only a `manifest.json` (no service worker, no Web Push). Any
   notification path is new client surface.

The design works **around** these (restore addressability without a directory; add push only when
unavoidable), never through them.

## 3. The per-app notification channel (opt-in, set at first consent)

To be reachable without a directory, the **wallet** mints a channel **at the user's first
authorization** of that app and hands it over:

- `channelId` — opaque, derived **per audience** so it's unlinkable across apps:
  `HKDF(masterKey, salt="kunji-channel-v1", info="kunji-channel:"+audience)` (same family as `sub`).
- A **posting capability** — a holder-of-key token (the `kunji-cap+jwt` shape) that authorizes
  *whoever holds it* to post re-consent requests to `channelId`. The RP/agent stores it next to the
  user's `sub`. Only the holder can ping the channel; it carries no PII; it's **revocable** (kill the
  channel → the existing revocation pattern).

The channel says nothing to kunji about *who* the user is or *what* the app is — it's an opaque
mailbox the user consented to expose to exactly one audience.

## 4. Transport ① — RP notifies, kunji approves (recommended; zero new kunji infra)

Most apps already have their **own** relationship with the user (an account, a UI, maybe their own
push/email). Use it: the **RP** does the nudging through its own channel and **deep-links into the
wallet** with the pending request.

```
connected app  ──(its own UI/push/email: "tap to approve in kunji")──▶ user
user taps ──▶ deep link  https://app.kunji.cc/approve?req=<id|payload>  (opens the wallet)
wallet ──▶ shows the re-consent sheet ──▶ user approves ──▶ mints capability / presents VC
       ──▶ returns it to the RP over the encrypted return relay (agentSessions / agentCapabilityPoll)
```

- **No new kunji state, no push subscriptions, no directory** — kunji is just the approval surface
  and the (already-existing) encrypted return relay.
- The request payload can ride the deep link (small) or be fetched by `req` id from the existing
  agent request relay (`agentRequestRelay`), then decrypted client-side.
- Use this whenever the app has *any* contact with the user — which is most apps.

## 5. Transport ② — the opt-in kunji push relay (only when ① is impossible)

For a **headless agent** or an app with **no channel of its own to the user**, kunji can run a thin
**push relay** keyed by the opaque `channelId` from §3. This is a **deliberate, consented
relaxation** — the same shape as the agent capability relay kunji already runs, but **persistent +
push-capable**.

### 5.1 Registration (at first consent, with the user's permission)

The wallet adds a service worker + Web Push (VAPID), requests the OS notification permission, and
registers its push subscription **against the per-app `channelId`** in a kunji relay:

```
pushChannels/{channelId} = {
  pushSub: <ciphertext or opaque endpoint+keys>,   // the Web Push subscription
  postKeyJwk: <OKP jwk>,                            // who may post (holder-of-key)
  ecdhPubE:  <wallet ECDH pub for encrypted payload return, like agentSessions>,
  expiresAt, ttl
}
```

### 5.2 Request → push → approve → deliver

```
agent/app ──POST {channelId, encryptedRequest, postProof}──▶ pushDispatch (kunji Fn)
            └ verifies postProof against postKeyJwk (holder-of-key), rate-limits per channel
pushDispatch ──Web Push (opaque pointer only)──▶ wallet service worker
wallet ──fetch encryptedRequest by id ──▶ decrypt client-side ──▶ re-consent sheet
user approves ──▶ mint capability / present VC ──▶ deposit ECDH-encrypted into the return relay
agent/app ──poll agentCapabilityPoll──▶ decrypt ──▶ use
```

- The **push payload carries only an opaque pointer** (a request id), never the scope/VC details —
  kunji's push infra sees ciphertext + an id, never the request contents (reuse the ECDH-encrypted
  relay pattern from `agentic-delegation.md`).
- The request itself is **ECDH-encrypted to the wallet** and fetched/decrypted client-side.
- The return hop is the **existing** `agentSessions` + `agentCapabilityPoll`.

## 6. The re-consent sheet (what the user actually approves)

Either transport ends at the same wallet UI:

> **example.com** (already connected) requests:
> • `payments:charge` — up to **$50** for **acct_123**
> • verify **you're over 18** (from issuer.example)
> [ approve selected ] [ deny ]

Per-item, default-deny (§4 of [`scope.md`](./scope.md)); the result is a new/broader capability
(chain or re-mint) and/or a VC presentation. The agent that hit `insufficient_scope` simply retries
with the new capability.

## 7. Invariants — preserved vs new surface (be explicit)

**Preserved**

- **Backendless login path** — the capability/VC is still minted client-side and verified by the RP
  **locally**; kunji only moves ciphertext (and, in ②, a push pointer).
- **Per-app unlinkability** — `channelId` is per-audience, unrelated across apps; kunji can't
  correlate channels.
- **Anonymity & holder-of-key** — the channel is an opaque token (no PII); only the holder of the
  posting capability can ping it; only the human approves.
- **Revocable** — muting/killing a channel reuses the revocation pattern.

**New surface (this is why ① is preferred over ②)**

- ② adds **persistent push-subscription state** in kunji (opaque, but more than "ciphertext +
  scale-to-zero"); **per-channel timing metadata** (kunji sees "channel C pinged at T", not who/what);
  a **spam vector** (a connected app could nag); and a **new client attack surface** (service worker +
  Web Push + a notification permission prompt). ① has none of these.

## 8. Abuse, cost & privacy controls (for ②)

- **Holder-of-key posting** — only the holder of the channel's posting capability can dispatch; third
  parties can't push.
- **Rate limits** per `channelId` and per IP (the `agentic-delegation.md`/`ops-cost-controls.md`
  pattern); `maxInstances` on `pushDispatch`; add it to the cost table in
  [`ops-cost-controls.md`](./ops-cost-controls.md) when built.
- **User mute/revoke** per channel, surfaced in the wallet's connected-apps list.
- **Ciphertext-only payloads**; push carries an opaque pointer; rotate `channelId` on revoke.
- **TTL + Firestore TTL policy** on `pushChannels`/relay docs.

## 9. Data model & rules sketch (for ②)

```
pushChannels/{channelId}      // create by authed wallet; read/post mediated by a Function
agentSessions/{sessionId}     // EXISTING — the encrypted return hop, reused verbatim
```

`firestore.rules`: `pushChannels` is **deny-all to clients** except the wallet's own create; reads
and posts go through the `pushDispatch` Function (Admin), exactly like `agentRequests`/`agentSessions`
today. The posting capability (holder-of-key) — not Firebase auth — is what authorizes a dispatch, so
the unauthenticated agent never touches the doc directly.

## 10. When NOT to use the push relay

If the RP can reach the user through its **own** app/UI/notification — **use Transport ① and skip the
relay entirely.** ② exists only for the genuinely channel-less case (headless agents, or an explicit
"let kunji be the notifier" product choice). Defaulting to ② would re-introduce persistent,
metadata-bearing state that kunji otherwise doesn't keep.

## 11. Phasing

1. **Step-up via ①** — `insufficient_scope` → re-request → deep link → re-consent sheet → existing
   return relay. Needs only the scope engine + VC presentation + a `/approve?req=` deep link. **No new
   kunji infra.**
2. **Push relay ②** — service worker + Web Push in the wallet, `pushChannels` + `pushDispatch`,
   opt-in registration, cost-controls entry. Gate behind a clear product decision.

## 12. Open decisions

- Deep-link payload: inline vs `req`-id fetch (recommended: id fetch via the existing request relay
  for anything non-trivial).
- `channelId` lifetime & rotation policy.
- Whether the posting capability is the same `kunji-cap+jwt` minted with a `channel:post` scope (reuse
  [`scope.md`](./scope.md)) or a distinct token type. Recommendation: reuse `kunji-cap+jwt` with a
  reserved `channel:post` scope.
- Web Push provider/VAPID key custody.

## 13. Where it will live (when built)

- Deep link + re-consent sheet → the wallet (`src/components/`), reusing the agent/login approval UI.
- ② service worker + push subscription → `public/` + `src/` (new PWA push plumbing; the app currently
  ships only `manifest.json`).
- `pushDispatch` + `pushChannels` → `functions/index.js` (codebase `app`) + `firestore.rules`, with a
  row in [`ops-cost-controls.md`](./ops-cost-controls.md).
- Return hop → reuse `agentCapabilityPoll` / `agentSessions` unchanged.
