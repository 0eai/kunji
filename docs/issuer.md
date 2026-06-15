# kunji age issuer (`issuer.kunji.cc`)

kunji's first **real, production credential issuer**: an age credential (`vct: 'age'`) that a user obtains
once — after a third-party identity-verification (IDV) check of their age — and then presents, unlinkably,
to any relying party that trusts kunji. The credential carries **boolean thresholds only**
(`age_over_13/16/18/21`), **never a date of birth**. This is the opposite trust posture from the kunji
**wallet** (which is zero-knowledge and sees nothing): the issuer is a *trusted third party* that verifies
age once and signs an assertion others rely on. The two are deliberately separate origins and brands.

> Status: **Phases 0–3 built** (faithful origin + key set + StatusList; the Persona IDV proofing gate; the
> admin console). Un-deployed; designed to be proven against Persona's **sandbox**. Production go-live (live
> IDV keys + DPA + compliance) and the end-to-end product also depend on non-engineering work — see *Trust &
> compliance* below. (IDV vendor = **Persona**: Stripe Identity isn't available to a South Korea–based
> operator, and the `idv/*` adapter is swappable, so the proofing provider was pointed at Persona.)

## How an age credential is obtained (target flow, Phase 2)

1. The user opens `issuer.kunji.cc` and starts age verification.
2. The issuer creates a session with an **IDV vendor** (ID-document + liveness; **Persona** is the reference
   adapter — `idv/persona.js`). The vendor holds the document/biometric and its legal liability.
3. The vendor's signed webhook returns a pass/fail + verified age. The issuer stores **only** the derived
   `age_over_N` booleans + a vendor verification id (for audit) — **never the DOB or document** — on a
   short-TTL `idvSessions` doc, marked `verified`.
4. Only a `verified` session yields an OpenID4VCI **credential offer** (a single-use pre-authorized code).
   The user scans it (or taps the `app.kunji.cc/?offer=` deep link) into their kunji wallet.
5. The wallet runs token → credential; the issuer mints the SD-JWT VC bound to the wallet's holder key,
   allocates a StatusList index, and writes a data-minimized ledger row.

In **Phase 1** steps 1–4 are stubbed: issuance is **closed** (`503 issuance_not_enabled`) unless
`ISSUER_OPEN_MINT=true`, which mints from a default age (no proofing) purely to prove the cross-origin trust
path with a throwaway credential. Open-mint must be OFF before any RP is told to trust this issuer.

## Architecture

- **Hosting:** `issuer.kunji.cc` (Hosting site `issuer-kunji-cc`) + `admin.kunji.cc` (`admin-kunji-cc`), both
  in the existing `kunji-cc` project. Functions live in a **separate codebase `issuer`** (`issuer-functions/`,
  Node 20), isolated from the wallet's `app` codebase so deploys never prune each other.
- **Origin:** `ISSUER_ORIGIN` (env) is the `credential_issuer`/`iss` and the origin a verifier resolves keys
  from. Defaults to `https://issuer-kunji-cc.web.app` (works before the custom-domain DNS is live); flip to
  `https://issuer.kunji.cc` once DNS lands. Pick the FINAL origin before issuing any credential a user keeps.
- **Signing key:** the Firebase Secret **`KUNJI_ISSUER_SIGNING_KEY`** — deliberately a *different* name from
  the kunji-demo's `ISSUER_SIGNING_KEY` (Secrets are project-scoped; reusing the name would make the real
  issuer sign with the demo's mints-to-anyone key — see SECURITY_AUDIT S31). It is a rotation-capable **key
  SET**: a bare base64 Ed25519 secret key, OR a JSON array `[{ kid, sk, active? }]`. Signing uses the active
  key; `.well-known/kunji-issuer.json` publishes **every** public key so a credential signed by a retired
  key still verifies until it expires.
- **Firestore (namespaced, deny-by-default; Admin-SDK writes only):** `issuerOffers`, `issuerTokens`,
  `issuerStatusList` (the revocation list), `issuerRateLimits`, `issuerCredentials` (the data-minimized
  issuance ledger: vct, idx, kid, the booleans, vendor ref, issuedAt — **no PII**), plus `idvSessions` (P2)
  and `issuerAdmins` (P3). None collide with the wallet's or the demo's collections.

### Endpoints (`issuer-functions/index.js`, mapped via `firebase.json` rewrites)

| Path | Function | Purpose |
|---|---|---|
| `/.well-known/openid-credential-issuer` | `issuerOidcMetadata` | OpenID4VCI metadata |
| `/.well-known/oauth-authorization-server` | `issuerOauthMetadata` | OAuth AS metadata |
| `/.well-known/kunji-issuer.json` | `issuerKeys` | **Trust anchor** — the published public key SET |
| `/credential-offer` | `issuerOffer` | Mint a single-use offer (gated: `503` unless open) |
| `/token` | `issuerTokenEndpoint` | Redeem pre-auth code → access token + c_nonce |
| `/credential` | `issuerCredentialEndpoint` | Verify holder proof → mint SD-JWT VC + ledger |
| `/status/1` | `issuerStatusEndpoint` | StatusList check (`valid:false` ⇒ revoked) |

The SD-JWT VC core (`mintCredential`) and OpenID4VCI helpers (`verifyProofJwt`, DPoP, PKCE) are reused from
the wallet lib via byte-identical Node ports `issuer-functions/{vc.js,oid4vc.js}` (parity-guarded by
`tests/{vc,oid4vc}.parity.test.js`). `issuer.js` adds the key set + age claims.

## RP / verifier side (faithful trust path)

A relying party that trusts kunji verifies a presented age credential by fetching
`${iss}/.well-known/kunji-issuer.json` **cross-origin** to get the issuer's key set (HTTPS-only; pin/allowlist
the trusted `iss` and cache). The kunji **wallet is never in the verify path**. The reference RPs
(`kunji-node-demo`, and the kunji-demo verifier once re-pointed) demonstrate this real cross-origin fetch —
replacing the demo's old `localIssuerKeys` shortcut (which only trusted its own origin).

## Admin console (`admin.kunji.cc`)

A standalone Vite+React SPA (`admin/`, its own `package.json`) for issuer operators: the **issuance ledger**
(non-PII rows + revocation status), **revoke/un-revoke** (toggles `issuerStatusList/age.revoked` → a verifier's
`/status/1` check then returns `valid:false`), the **IDV funnel + issuance stats**, and a **read-only key set**
view. It calls one auth-gated Function, `issuerAdminApi` (in the `issuer` codebase), at `admin.kunji.cc/api/*`.

**Auth = Google sign-in + the `admin:true` custom claim.** Being signed in is NOT enough — the same `kunji-cc`
project mints anonymous wallet tokens, so `issuerAdminApi` requires the claim, and the admin API holds **no
signing secret** (it reads keys from the public `.well-known`), so it can revoke/read but never sign or rotate.

Grant an operator (one-time; they must sign in to `admin.kunji.cc` once first so the account exists):
```
cd issuer-functions
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json node scripts/grant-admin.js you@example.com
# then the operator signs out + in again to refresh the token with the claim. `--revoke` removes it.
```
Enable **Google** as a sign-in provider in the Firebase console and add `admin.kunji.cc` (+
`admin-kunji-cc.web.app`) to the Authorized domains.

## Key rotation (manual runbook)

Rotation is intentionally a CLI step (the admin Functions never get secret-write power). `KUNJI_ISSUER_SIGNING_KEY`
accepts a JSON **key set** `[{ "kid", "sk", "active" }]`. To rotate: generate a new Ed25519 key, set the secret
to a set with the NEW key `active:true` and the previous key(s) retained (so credentials signed by a retired
key keep verifying until they expire), then redeploy `functions:issuer`. Prune a key only after every
credential it signed has expired. The admin "Signing keys" view shows the currently published kids.

## Deploy

```
firebase target:apply hosting issuer issuer-kunji-cc
firebase target:apply hosting admin  admin-kunji-cc
firebase functions:secrets:set KUNJI_ISSUER_SIGNING_KEY      # base64 Ed25519 secret (or a JSON key set)
firebase functions:secrets:set PERSONA_API_KEY              # Persona API key (sandbox to start)
firebase functions:secrets:set PERSONA_WEBHOOK_SECRET       # the webhook secret from the Persona dashboard
# PERSONA_INQUIRY_TEMPLATE_ID (itmpl_…) and optional PERSONA_VERSION are env (issuer-functions/.env) — non-secret.
cd admin && npm install && npm run build && cd ..             # → admin/dist (the admin Hosting target)
firebase deploy --only "functions:issuer,hosting:issuer,hosting:admin,firestore:rules"   # explicit — never a bare deploy
```

**IDV vendor setup (Persona):** create a "Government ID + Selfie" inquiry template → set `PERSONA_INQUIRY_TEMPLATE_ID`;
add a webhook in the Persona dashboard pointing at `https://issuer-kunji-cc.web.app/idv/webhook` (the `.web.app`
URL until the custom-domain DNS is live) and put its signing secret in `PERSONA_WEBHOOK_SECRET`. Confirm your
account onboards a South Korea–based operator. Build/verify against Persona's **sandbox** before production.

Leave `ISSUER_OPEN_MINT` unset (closed) in production. To prove the Phase-1 cross-origin verify path, set it
`true` temporarily, mint one credential, verify it via a real RP, then turn it off.

## Trust & compliance (non-engineering — gates go-live, not in the code)

The engineering is the easy part. Before kunji is a *trusted* age issuer it also needs: a contracted IDV
vendor + DPA; a GDPR/data-controller posture for the transient verified-age result; awareness of
age-verification regulation in target markets (UK OSA, US state laws, EU age-assurance); issuer Terms + a
relying-party trust basis (why an RP accepts `iss: issuer.kunji.cc` — initially explicitly pinned partners,
later certification/track record); and liability. See the plan and `docs/verified-credentials.md`.
