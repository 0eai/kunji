# Kunji Discoverable Login — Protocol Design

**Status:** Implemented (v2 discoverable) — shipped in the kunji wallet, the `rp.js` drop-in widget, and a working demo relying party. See §13 for where the code lives.
**Scope:** How any multi-user app replaces Google / password sign-in with "Sign in with kunji",
without kunji sharing any database with the app.

---

## 1. Goals & Constraints

**Goals**

- Let _any_ kunji user log into a shared, publicly-deployed app (the RP) — not just a pre-provisioned one.
- No central developer registry, no app-approval console, no kunji-as-platform. Self-sovereign: the user _is_ their key.
- Drop Google/Firebase social auth entirely; preserve existing Firestore security rules.

**Hard constraints**

- 🔒 **Kunji shares NO database with the RP or any other app.** Kunji's Firestore/RTDB store only the user's
  own encrypted vault (their per-app keypairs). The app stores its own sessions and user records in its own backend.
- 🔒 **Kunji runs no backend in the cross-app login path.** The wallet is a pure client: scan → sign → POST.
  The _relying app_ owns the session channel end to end.

**Consequence of the constraints**
The only two cross-boundary channels are:

1. The **QR code** (app → wallet, through the user's camera).
2. A **signed assertion HTTP POST** (wallet → the app's own public callback URL).

There is no shared storage and no kunji service in the middle.

---

## 2. Roles & Trust Model

| Role                   | Who       | Holds                                                                                                   |
| ---------------------- | --------- | ------------------------------------------------------------------------------------------------------- |
| **Wallet**             | kunji PWA | The user's per-app Ed25519 keypairs, in kunji's own encrypted vault. Nothing about app sessions.        |
| **Relying Party (RP)** | the RP    | Its own session store + user records (keyed by public key), in the RP's own DB. A small verifier backend. |
| **User**               | human     | Approves each login in the wallet; visually confirms the app domain.                                    |

**Trust model: self-sovereign keys.** The RP trusts whatever public key the wallet presents and verifies a
signature over a fresh challenge. First time it sees a public key → new account; a returning key → existing account.
This is the SSH / Nostr / passkey model. There is no authority vouching for identity — and for the RP's
self-hosted, privacy-first ethos, that is the correct model.

---

## 3. Data Ownership (the no-shared-DB boundary)

```
┌────────────────────────── kunji (wallet) ───────────────────────────┐
│  kunji vault (kunji's OWN Firestore, encrypted):                    │
│    users/{kunjiUid}/apps/{appKeyId} = {                             │
│       appDomain, name, iconUrl,                                     │
│       encryptedPrivateKey,  publicKey                               │
│    }                                                                │
│  ▸ Keyed by appDomain. Auto-created on first login to a domain.     │
│  ▸ Never contains app session data. Never read by the app.          │
└─────────────────────────────────────────────────────────────────────┘
                 │  QR (app→wallet)        ▲  signed assertion POST (wallet→app)
                 ▼                         │
┌────────────────────── the RP (relying party) ───────────────────────┐
│  the RP's OWN backend + DB:                                         │
│    loginSessions/{sessionId} = { challenge, status, assertion? }    │
│    users/{sub} = { kunjiPublicKey, ...app data }                    │
│  ▸ the RP never reads kunji's DB. kunji never reads the RP's DB.    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Protocol Flow (discoverable login)

```
 ┌─RP frontend───┐         ┌─user─┐        ┌─kunji wallet─┐      ┌─RP backend───┐
 │               │         │      │        │              │      │ (Cloud Fn)   │
 │ 1. start login│────────────────────────────────────────────▶ │ createSession│
 │               │◀──────── { sessionId, challenge } ─────────── │              │
 │ 2. render QR  │         │      │        │              │      │              │
 │   (see §5.1)  │         │      │        │              │      │              │
 │               │  scan   │      │  3.    │              │      │              │
 │               │────────▶│─────────────▶ │ verify domain│      │              │
 │               │         │      │        │ + approve UI │      │              │
 │               │         │ 4. approve ──▶ │ sign challenge      │              │
 │               │         │      │        │ 5. POST assertion ──────────────▶ │ /callback
 │               │         │      │        │              │      │ verify+store │
 │ 6. poll ──────────────────────────────────────────────────▶ │ pollSession  │
 │               │◀──────── { status: approved, customToken } ── │ mint token   │
 │ 7. signInWithCustomToken(token) → Firebase uid = sub          │              │
 │ 8. the RP vault unlock (passphrase) proceeds as today         │              │
 └───────────────┘         └──────┘        └──────────────┘      └──────────────┘
```

Steps in words:

1. **createSession** — the RP's backend creates `loginSessions/{sessionId}` with a random `challenge` and short TTL.
2. **QR** — the RP renders a QR encoding the session + the RP's callback URL + the audience domain (§5.1). The QR contains **no user identifier**.
3. **Scan & verify** — kunji parses the QR, shows the user the **audience domain** ("example.com wants to verify you"). If the user has no key for `example.com` yet, kunji generates one locally (first login == registration). It displays the per-app `sub` ("shared as ab12…cd34").
4. **Approve** — user approves; kunji signs the assertion (§5.2) with the per-app private key.
5. **POST** — kunji POSTs the signed assertion to the `callbackUrl` from the QR. Kunji writes nothing to any shared store.
6. **Poll** — the RP's frontend polls the RP's backend; backend verifies the assertion (§6), upserts the user, mints a Firebase custom token (§7).
7. **Sign in** — the RP calls `signInWithCustomToken` → `request.auth.uid = sub`. Existing Firestore rules work unchanged.
8. **Vault** — the RP's existing passphrase-based vault unlock proceeds as today (unchanged). See §9.2 for the two-passphrase caveat.

---

## 5. Message Formats

### 5.1 QR payload (RP → wallet)

```json
{
  "kunjiAuth": "v2",
  "sessionId": "8f3c…",
  "challenge": "random nonce (hex or base64url — opaque to the wallet)",
  "audience": "example.com",
  "appName": "Example",
  "expiresAt": 1750000000000,
  "scope": ["profile"]
}
```

Rules:

- Required: `kunjiAuth:"v2"`, `sessionId`, `challenge`, `audience`, `expiresAt`.
- **Lean QR (recommended).** `mode`, `callbackUrl`, `returnUrl` are **optional** — omit them to keep
  the QR low-density:
  - `mode` defaults to `"discoverable"` (the only v2 mode).
  - `callbackUrl`, when omitted, the wallet derives **`https://{audience}/kunji/callback`** (the
    common same-origin case). RPs whose callback differs — a custom path, or a decoupled host like
    the relay demo, or local `http://localhost:PORT` dev — **MUST include `callbackUrl`** explicitly.
  - `returnUrl` is a same-device-only convenience; put it in the `?approve=` **deep-link** payload,
    not the QR (it's the longest, most variable field). Older/full QRs that still carry these fields
    parse unchanged — this is a backward-compatible relaxation of v2, no version bump.
- `sessionId`/`challenge` are opaque tokens the wallet only echoes back; the RP picks the encoding.
  **base64url** is ~30% shorter than hex for the same entropy (a leaner QR) — recommended.
- `audience` is the domain the user is logging into. Kunji **displays it** and **signs it** (anti-relay).
- The provided-or-derived `callbackUrl` MUST be same-site as `audience` (kunji rejects otherwise); a
  derived callback is same-site by construction, so it can't be relayed cross-site.
- No `registeredAppId`, no `ownerUid` — discoverable login is user-agnostic.
- `scope` (optional, string array) — OAuth-style scopes the RP requests. Only `"profile"` is
  defined: it asks the wallet to **offer** sharing the user's custom name/avatar. The wallet shows
  a consent toggle (default OFF); the user may decline, so the RP must not depend on receiving it.
  Omit `scope` and the RP simply renders the default identity (§8.1).
- `v1` (the existing pre-registered flow) remains valid; see §11.

### 5.2 Signed assertion (wallet → RP callback)

```json
{
  "publicKey": "base64 Ed25519 public key (the user's identity for this app)",
  "signedPayload": {
    "sessionId": "8f3c…",
    "challenge": "64-hex-byte nonce (echoed back)",
    "audience": "example.com",
    "sub": "hex SHA-256 of publicKey",
    "timestamp": 1750000000123,
    "claims": { "name": "Ada Lovelace", "picture": "data:image/webp;base64,…" }
  },
  "signedToken": "base64 Ed25519 signature over canonical-JSON(signedPayload)"
}
```

- `sub = hex( SHA-256( utf8(publicKeyBase64) ) )` — the SHA-256 of the base64 public-key _string_, hex-encoded. Self-contained, no kunji UID involved. Stable per (user, app), different across apps. (Implemented as `deriveSubFromPublicKey` in `src/services/identity.js`; the RP recomputes it via `subFromPublicKey` in `examples/kunji-login-demo/functions/verify.js`.)
- Signature uses the existing `signWithEd25519` canonical-JSON scheme already in `src/lib/crypto`.
- `claims` (optional) is present **only** when the user consented to share a custom profile
  (requested via `scope`, §5.1). It is part of `signedPayload`, so it is tamper-evident — but it is
  **self-asserted and NOT verified by anyone**. The user can type any name and pick any picture, and
  may present different values to different apps. Treat it as untrusted input (§6.8). Fields:
  `name` (string, ≤60 chars) and/or `picture` (a small `data:` image URI). Absent ⇒ use §8.1.

### 5.3 Callback response (RP → wallet)

`200 { "status": "ok" }` on accept, `4xx { "error": "..." }` otherwise. The wallet shows success/failure;
it does not need the token (the token goes to the RP's _frontend_ via its own poll).

---

## 6. Verification Rules (RP backend MUST enforce)

1. **Session exists & fresh** — `sessionId` is known, not expired, `status == pending`.
2. **Challenge match** — `signedPayload.challenge` equals the session's stored challenge (anti-replay).
3. **Audience match** — `signedPayload.audience == "example.com"` (the RP's own domain). Rejects assertions
   phished/relayed for a different app.
4. **Signature valid** — verify `signedToken` over canonical-JSON(`signedPayload`) using the presented `publicKey`.
5. **sub integrity** — recompute `SHA-256(publicKey)` and confirm it equals `signedPayload.sub`.
6. **Freshness** — `timestamp` within ±2 min of server time.
7. **Single use** — mark the session consumed; reject re-submission.
8. **Treat `claims` as untrusted** — if present, `claims` is tamper-evident (covered by the
   signature in §6.4) but **not** verified: never use it for authentication or authorization, never
   trust a claimed email as proof of address. HTML-escape `name` before rendering; render `picture`
   only client-side as an `<img>` (https/`data:` only, **never** server-fetch it — that's an SSRF
   and tracking vector). It is a display convenience on top of `sub`, nothing more.

Only after all pass: upsert `users/{sub}` (storing `kunjiPublicKey = publicKey`), mint the token. The
`sub` is the account key; `claims`/the default identity (§8.1) are display only — store them in your
own profile record, do **not** put unverified claims into the custom-token claims.

---

## 7. Firebase Custom-Token Bridge (the one required backend piece)

The RP cannot avoid a tiny trusted function, because Firestore security rules need a real `request.auth.uid`.

```js
// RP Cloud Function (pseudo)
exports.kunjiPoll = onCall(async ({ sessionId }) => {
  const s = await getSession(sessionId);
  if (s.status !== 'approved') return { status: s.status };
  // assertion already verified at /callback (see §6)
  const uid = s.assertion.signedPayload.sub; // stable per-app id
  const token = await admin.auth().createCustomToken(uid, {
    kunjiPub: s.assertion.publicKey,
  });
  return { status: 'approved', customToken: token };
});
```

- `uid = sub` → existing Firestore rules (`request.auth.uid`) keep working verbatim.
- This function lives in **the RP's** project, not kunji's. Kunji still runs no backend.

---

## 8. Identity Model

> **kunji authenticates; the app owns the profile.** kunji is not an identity provider that vends
> verified attributes (no Google-style email/name/photo). It proves "the same person returned" via a
> stable, anonymous, per-app `sub`. The app stores its own profile (display name, avatar, and — if it
> needs one — a contact email collected directly from the user) keyed by that `sub`. For a suite, use
> **one consistent `audience`** across your apps to get one shared identity; different audiences yield
> unrelated, uncorrelatable identities.

- **Account key = the per-app Ed25519 public key.** The same kunji vault on any of the user's devices holds the
  same keypair → same `publicKey` → same account. Kunji recovery key restores the vault → restores identity.
- **`sub = hex(SHA-256(utf8(publicKeyBase64)))`** (exact encoding in §5.2) is the stable string id the RP uses as the Firebase `uid`.
- **Per-app pseudonymity preserved** — keypair is per `appDomain`, so two apps see unrelated keys/subs and cannot
  correlate the user. (Consistent with the `deriveSubFromPublicKey` per-app derivation already in `identity.js`.)

### 8.1 Default pseudonymous identity (derived from `sub`)

So an app never has to show a blank placeholder or a raw hex `sub`, every `sub` maps to a friendly
**display name** and a kunji **key-sigil** avatar — both pure, deterministic functions of `sub`
(which the RP already has). No PII, no extra round-trip, no kunji infrastructure: distinct per app,
stable per app, unlinkable across apps. The RP renders them itself (`window.kunji.handle(sub)` from
`rp.js`, or by reimplementing the algorithm below). The canonical implementation is
`src/lib/kunjiHandle.js` + `src/lib/kunjiHandle.wordlists.js`; `window.kunji.handle(sub)` returns
`{ name, avatarSvg, avatarDataUri }`.

Algorithm (treat `sub` as 32 bytes = the 64-hex digest; both halves are used independently):

- **Name** = `"{Adjective} {Surname}"` where, reading from byte offset 16 (so the name varies
  independently of the sigil, which reads from the front),
  `Adjective = ADJECTIVES[idx % ADJECTIVES.length]` and `Surname = NAMES[idx % NAMES.length]` (each
  `idx` consumes two bytes, big-endian). `sub` remains the real key — names may collide, that's fine.
  The two wordlists are the canonical lists in `kunjiHandle.wordlists.js`.
- **Key-sigil** = a fixed-treatment **amber wax-seal disc** (vertical gradient + darker rim, hue/
  saturation/lightness drifting slightly within the amber family) bearing an **embossed ink key**.
  A sequential byte-reader over `sub` (from the front) sets the key geometry: bow ring radius + hole,
  an inner motif (`none|dot|diamond|cross|ring`), shaft width, and 4–6 bit-teeth cut from a
  deterministic pattern (the tip tooth always present). Output is a self-contained `viewBox="0 0 96
  96"` SVG (no script/external refs); the amber treatment is **fixed** (not theme-dependent) so every
  RP renders the same sigil. The sigil doubles as a visual key-fingerprint. See `keySigilSVG` in
  `kunjiHandle.js` for the exact geometry — RPs should call `window.kunji.handle(sub)` rather than
  reimplement it.

⚠️ This algorithm + the wordlists are a **rendering contract** shared by the wallet, `rp.js`, and any
third-party RP. Changing them re-skins every user's default name/avatar (cosmetic — never a lockout,
since `sub` is unchanged), so treat any change as a versioned break. (The v0.1.x key-sigil + surname
identity replaced an earlier grid-identicon + "Adjective Noun NN" scheme — a one-time re-skin.)

If the user shared a custom profile, the assertion carries `claims` (§5.2) — prefer it over the
default, but render it as untrusted input (§6.8).

### 8.2 Organization identity (shared `audience`)

`sub` is derived per **`audience`**, and the **RP chooses its `audience`** (§5.1). An organization that
points all of its apps at **one shared audience** therefore gets the **same `sub`** for a user across
its suite — a built-in, opt-in SSO with no global identifier and no kunji-side registry:

- e.g. `hr.acme.com`, `payroll.acme.com`, and `intranet.acme.com` all declaring `audience: "acme.com"`
  resolve to the **same `sub`** for a given user → the org can recognize the same employee everywhere.
- Subdomains may POST to that parent audience because the callback check is same-site
  (`host === audience || host.endsWith('.' + audience)`, §6.4) — so `payroll.acme.com` with
  `audience: "acme.com"` and `callbackUrl: https://payroll.acme.com/...` is accepted.
- **Cross-org unlinkability is preserved:** a user's `acme.com` `sub` is unrelated to their `sub` at any
  other org or standalone app. Linkage is scoped to whoever shares the audience, by the RP's choice.

This is why kunji has **no global "same identity everywhere" wallet switch** — that would break
unlinkability for *every* app at once. Organization linkage is the RP's deliberate, scoped decision.

⚠️ **Guardrail:** the audience must be a registrable host the org controls — never a bare public suffix
(`com`, `co.uk`) or a shared platform domain. A public-suffix audience would link unrelated tenants and
defeats the anti-relay same-site check (§9.2, the public-suffix caveat). Apps on a shared SaaS host
(`tenant.platform.com`) must use their **own** audience, not the platform's.

---

## 9. Security & Operational Considerations

### 9.1 Threats handled

- **Replay** — challenge is single-use and session-bound (§6.2, §6.7).
- **Relay / phishing** ("evil app shows the RP's QR") — audience binding (§6.3) + user sees the domain in the
  approval UI (existing `domainMismatch` check in `ApprovalModal.jsx`).
- **MITM on callback** — `callbackUrl` must be HTTPS and same-site as `audience`; kunji rejects otherwise.
- **Key compromise** — keys never leave the vault; only signatures are emitted.

### 9.2 Caveats to design around (call out in onboarding)

- **Recovery coupling.** The kunji vault key is now the root of the user's access to the RP. Lose the kunji vault
  _and_ its recovery key → lose access to the RP. Kunji's recovery key is now load-bearing for every connected app.
- **Two-passphrase seam.** The RP still has its own vault passphrase. After this change the user holds two secrets
  (kunji vault + RP vault). Acceptable for v1; the eventual fix (kunji provisioning the RP's encryption key for a
  single-passphrase experience) is **out of scope** here — noted in §12.
- **Local-only apps.** Apps with no public HTTPS callback (localhost/home-server) can't receive the POST from a
  phone wallet directly. Out of scope for v1; see §12.

---

## 10. What Kunji (wallet) Must Add

- **Discoverable QR parsing** — accept `kunjiAuth: "v2", mode: "discoverable"`; require `audience` + same-site `callbackUrl`.
- **Auto-registration on first scan** — if no keypair exists for `appDomain`, generate and store one in the vault
  (reuse `registerApp` internals, keyed by domain).
- **Assertion signer + POST** — build `signedPayload` (§5.2), sign with the per-app key, `fetch(callbackUrl, { method: POST })`.
  No kunji backend, no kunji DB writes outside the user's own vault.
- **Approval UI** — already shows app + domain + truncated `sub`; just needs to render from the v2 QR fields.

No changes to kunji's storage model and **no kunji-side session storage for other apps** — satisfying the no-shared-DB constraint.

## 11. What the Relying Party Must Implement

> **MUST:** the RP **hardcodes its own `audience` and `callbackUrl` server-side** in `createSession` and ignores any client-supplied values. The demo reads them from the request body for convenience only — accepting them from the client in production lets a caller mint sessions claiming an arbitrary domain. The RP **MUST** also consume each session atomically (verify + mark `approved` in one transaction) and cap failed code lookups (per-IP limiting alone is `X-Forwarded-For`-spoofable).

- `createSession` + `pollSession` endpoints over **the RP's own** session store.
- `/kunji/callback` endpoint implementing the §6 verification.
- The §7 custom-token mint.
- A read-only **status/poll** endpoint (`GET ?sessionId=` → `{ status, sub, customToken? }`) the frontend/widget polls until `approved`.
- Frontend: render the v2 QR, poll, `signInWithCustomToken`, then proceed to existing vault unlock.
- A drop-in widget is **shipped** so RPs don't have to build the UI: `<script src="https://kunji.cc/rp.js">` renders the button, opens the QR / OTP modal, and polls the status endpoint — see §13.

---

## 12. Modes & Future Work

- **Discoverable (v2)** — primary, multi-user, user-agnostic QR. This document.
- **Pre-registered (v1)** — existing personal/self-hosted flow where a specific keypair is provisioned ahead of time.
  Remains valid; both modes share the §5.2 assertion + §6 verification shape.

- **Default + custom identity (shipped)** — every `sub` has a deterministic default name + identicon
  (§8.1); the user may optionally share a self-asserted custom profile per-app via the `profile`
  scope + signed `claims` (§5.1, §5.2, §6.8).
- **Agentic delegation (shipped)** — a user can authorize an autonomous agent to act for them at one
  app via a holder-of-key, scoped, expiring, revocable **capability** the wallet signs with the
  per-app key (never the keys themselves), plus an MCP signing bridge. Preserves the §8 per-app
  unlinkability and the human-approval trust root. Spec:
  [`agentic-delegation.md`](./agentic-delegation.md).

**Future (explicitly out of scope now):**
- Kunji provisioning the app's encryption key → single-passphrase UX (collapses the §9.2 two-passphrase seam).
- Local/LAN app login (loopback or same-device `postMessage` channel).
- **Verified credentials (planned).** Today all shared `claims` are **self-asserted** (signed by the
  per-app key, but the RP must treat them as untrusted — §6.8). The valuable extension is **issuer-signed
  attestations**: a trusted issuer (a university, employer, age-verification provider) signs a credential
  ("over 18", "student at X", "employee of Y"); the wallet later presents it to an RP with **selective
  disclosure**, verifiable **without kunji in the path** (the same backendless trust model as §6, just a
  different signer). This is a substantial effort — issuers, credential schemas, and DID/VC-style
  verification — tracked as future work.
  - **Non-goal: RP-requested self-asserted attributes** (an app asking the user to *type* a DOB / student
    ID / employee ID at approval). Unverified data typed into kunji is no more trustworthy than the same
    field in the RP's own form, and it pushes sensitive PII into a zero-knowledge wallet for no assurance
    gain. RPs should collect such fields in their own UI; kunji's value here is *verified* claims, above.

---

## 13. Implementation & reference (where the code lives)

**Wallet — the kunji PWA (this repo):**

- v2 QR parsing, idempotent per-domain key registration, the assertion signer + POST, and `deriveSubFromPublicKey` → `src/services/identity.js`.
- Approval UI (app + domain + truncated `sub`, "first time here", expiry) → `src/components/ApprovalModal.jsx`.
- Crypto (Argon2id, AES-GCM, Ed25519, canonical-JSON signer) → `src/lib/crypto/`.

**Relying-party reference — `examples/kunji-login-demo/`:**

- `functions/index.js` — `createSession` (challenge + TTL + 6-digit code), `lookupSession` (resolve a typed code, rate-limited), `getSessionStatus` (read-only poll → `{ status, sub }`), `kunjiCallback` (the wallet POSTs the signed assertion here).
- `functions/verify.js` — `canonicalJson`, `subFromPublicKey`, and `verifyAssertion` enforcing all of §6.
- `firebase.json` — Hosting rewrites mapping `/kunji/session`, `/kunji/status`, `/kunji/callback` to those functions (so the callback is same-site as the audience).
- Firestore rule for `loginSessions` (get-only; writes are server-only via Admin) → root `firestore.rules`.

**Other relying-party references:**

- `examples/kunji-node-demo/` — the same protocol with **no Firebase, no framework** (plain Node `http` + `@noble/curves`, in-memory sessions) and a wallet simulator for local end-to-end testing.
- `examples/kunji-agent-demo/` — `kunji-node-demo` plus **agent logins**: the same §6 human login *and* a `POST /kunji/agent` endpoint that accepts a holder-of-key **capability** (agentic delegation). The runnable, zero-infra target for `examples/kunji-mcp` (the **MCP bridge** that lets an AI runtime act for a user via a user-authorized capability — never the keys).
- `examples/kunji-relay-demo/` — a **local** RP (dynamic IP, behind NAT) that rendezvous with the phone via a thin public callback Function + Firestore, so you can test with a **real phone, no tunnel**. Verifies §6 at the edge; the local server listens outbound. (Caveat: the `sub` is then bound to the relay's Firebase domain, not your production audience.)
- `examples/kunji-selfhosted-demo/` — the **production** self-hosted shape: your own Firebase (Hosting + **custom domain** → real production `sub`, Auth **custom token** per §7, Firestore accounts) as the public front door, plus an **on-prem worker on a dynamic IP** that reacts to logins over an outbound listener. No tunnel.

**Drop-in widget — `rp.js`:**

- Source `widget/src/index.js`, bundled to `landing/rp.js` (+ pinned `rp.v1.js`), served at `https://kunji.cc/rp.js`.
- Renders the official "Sign in with kunji" button in a shadow root, opens the QR / OTP modal + same-device deep link, and polls the RP's own status endpoint — then fires `kunji:success` (`{ sub, customToken? }`) or redirects. Pure client: it talks only to the RP's endpoints, never to a kunji server.

**Developer guides (live):**

- `https://kunji.cc/developers` — stack-agnostic protocol guide.
- `https://kunji.cc/developers/firebase` — end-to-end Firebase guide (widget-first, then the functions/rules above).
- `https://kunji.cc/developers/try` — the widget running live against the demo's endpoints.
