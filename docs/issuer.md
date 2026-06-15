# kunji age issuer (`issuer.kunji.cc`)

kunji's first **real, production credential issuer**: an age credential (`vct: 'age'`) that a user obtains
once — after a third-party identity-verification (IDV) check of their age — and then presents, unlinkably,
to any relying party that trusts kunji. The credential carries **boolean thresholds only**
(`age_over_13/16/18/21`), **never a date of birth**. This is the opposite trust posture from the kunji
**wallet** (which is zero-knowledge and sees nothing): the issuer is a *trusted third party* that verifies
age once and signs an assertion others rely on. The two are deliberately separate origins and brands.

> Status: **Phases 0–2 built** (faithful origin + key set + StatusList; the Stripe Identity IDV proofing
> gate). Verified against Stripe **test mode**; un-deployed. **Phase 3** (the admin console) follows.
> Production go-live (live IDV keys + DPA + compliance) and the end-to-end product also depend on
> non-engineering work — see *Trust & compliance* below.

## How an age credential is obtained (target flow, Phase 2)

1. The user opens `issuer.kunji.cc` and starts age verification.
2. The issuer creates a session with an **IDV vendor** (ID-document + liveness; Stripe Identity is the
   reference adapter). The vendor holds the document/biometric and its legal liability.
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

## Deploy

```
firebase target:apply hosting issuer issuer-kunji-cc
firebase target:apply hosting admin  admin-kunji-cc
firebase functions:secrets:set KUNJI_ISSUER_SIGNING_KEY      # base64 Ed25519 secret (or a JSON key set)
firebase deploy --only "functions:issuer,hosting:issuer,hosting:admin"   # explicit — never a bare deploy
```

Leave `ISSUER_OPEN_MINT` unset (closed) in production. To prove the Phase-1 cross-origin verify path, set it
`true` temporarily, mint one credential, verify it via a real RP, then turn it off.

## Trust & compliance (non-engineering — gates go-live, not in the code)

The engineering is the easy part. Before kunji is a *trusted* age issuer it also needs: a contracted IDV
vendor + DPA; a GDPR/data-controller posture for the transient verified-age result; awareness of
age-verification regulation in target markets (UK OSA, US state laws, EU age-assurance); issuer Terms + a
relying-party trust basis (why an RP accepts `iss: issuer.kunji.cc` — initially explicitly pinned partners,
later certification/track record); and liability. See the plan and `docs/verified-credentials.md`.
