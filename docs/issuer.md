# kunji credential issuer (`issuer.kunji.cc`)

kunji's **production credential issuer**: an age credential (`vct: 'age'`) a user obtains once — after kunji
**verifies their age** — and then presents, unlinkably, to any relying party that trusts kunji. The
credential carries **boolean thresholds only** (`age_over_13/16/18/21`), **never a date of birth**. This is the
opposite trust posture from the kunji **wallet** (zero-knowledge, sees nothing): the issuer is a *trusted
third party* that verifies once and signs an assertion others rely on. Separate origin, separate brand.

> Status: **built (Phases 0–3 + v2 own-flow)**, un-deployed-as-v2. v1 used an external Persona redirect;
> **v2 removes Persona for kunji's own flow** and a **pluggable framework**. Go-live also depends on
> non-engineering work — see *Trust & compliance*.

## How an age credential is obtained (v2 — document review)

1. The user opens `issuer.kunji.cc` (a React app matching app.kunji.cc) and taps **Verify your age**.
2. `POST /verify/start {type:'age', method:'document-review'}` → a `verificationSessions` doc (`collecting`).
3. The user **uploads a government-ID photo** (resized + re-encoded to JPEG client-side, stripping EXIF) →
   `POST /verify/upload` → the image is stored in Firebase **Storage** (`verify-docs/{sid}`, private) and the
   session moves to `pending_review`.
4. An **operator** opens the **admin console** review queue, views the image (claim-gated, streamed — no
   public URL), confirms the **date of birth**, and **Approves** → the system derives the `age_over_N`
   booleans, marks the session `verified`, **deletes the image**, and stores only the booleans (+ reviewer/ts;
   never the DOB). Reject → `rejected` + image deleted.
5. The issuer page (polling `/verify/status`) sees `verified` → `GET /credential-offer?sid` → the
   `app.kunji.cc/?offer=` deep link → the wallet receives the SD-JWT VC; present `age_over_18` anywhere.

A daily `issuerCleanup` sweeps any abandoned upload (>24h) so an ID image never lingers.

## Pluggable framework (add types + methods without touching the core)

```
Credential TYPE registry  (issuer-functions/credentials.js)
  age            → buildClaims(dob)→age_over_13/16/18/21 booleans · reviewFields:[dob]
  residency      → buildClaims({country,region})→{country,region?}  · reviewFields:[country,region]
  gender         → buildClaims({gender})→{gender}                    · reviewFields:[gender (select)]
  verified_human → buildClaims(id)→{is_human:true} + nullifierFrom(id) (uniqueness) · reviewFields:[idType,country,idNumber]
        ← add a credential type = one entry { vct, label, ttlSeconds, methods, reviewFields, buildClaims, nullifierFrom? }

Verification METHOD registry  (issuer-functions/verify/)
  'document-review' (verify/documentReview.js): kind 'manual' — resolved by an operator review
        ← add a method = one module + one entry; future 'pass'/'aadhaar' add start()/callback (kind 'redirect'/'inline')

verificationSessions/{sid}  { type, method, status: collecting|pending_review|verified|rejected, claims, … }
```

Each type declares **`reviewFields`** (what the operator confirms — `text`/`date`/`select`); the admin
review panel renders them dynamically and posts a `verifiedData` object (a bare `dob` is still accepted for
the original age flow). `buildClaims(verifiedData)` is the **no-PII boundary**: raw inputs → coarse claims,
discarded after. `residency`/`gender` are coarse attributes (country/region, gender marker) with no
uniqueness.

### Uniqueness — `verified_human` + the nullifier (roadmap 2.2)

`verified_human` mints only `is_human: true` (never the ID number/name) and enforces **issuer-side
uniqueness**: the operator enters `(idType, country, idNumber)`; `nullifierFrom` produces a **FROZEN**
normalized pre-image (`verified_human|<CC>|<idType>|<NUMBER>` — uppercased, separators stripped, leading
zeros kept; **never change it** — that re-buckets every prior enrollee); `issuer-functions/nullifier.js`
turns it into a one-way **scrypt** digest keyed by the issuer-only secret **`KUNJI_NULLIFIER_KEY`**, recorded
in the deny-all `issuerNullifiers` collection (`{createdAt}` only). Re-verifying the same ID is **idempotent**
(one human, e.g. device loss — not a second identity); first-mint vs remint return identically (no
operator-facing membership oracle); the nullifier is **NEVER** in the credential/claims/ledger.

- **`KUNJI_NULLIFIER_KEY` is NON-ROTATING** — rotating it re-buckets everyone (raw IDs are discarded), so
  uniqueness silently breaks. (Distinct from `KUNJI_ISSUER_SIGNING_KEY`, which IS a rotation-capable set.)
- **Scope (be precise):** this delivers **issuer-side uniqueness** — the Sybil bar becomes "acquire N
  distinct real government IDs". It does **NOT** give an RP **per-app dedup** ("one account per human"):
  credentials present unlinkably (v2/v3), so an RP only learns "holds a verified-human credential". Per-app
  dedup = per-verifier pseudonyms (roadmap 4.1, deferred). **Caveats:** uniqueness = "one per
  *correctly-transcribed* ID" (operator-accuracy bound); one human with two ID documents → two credentials.
  See `docs/verified-credentials.md` §7.

The offer→token→credential path + `/status/{type}` + revoke are **type-agnostic**. Trust model: the issuer
**publishes brand + per-type verification methods** in its metadata so an RP can recognize WHO issued it +
HOW it was verified + the brand mark (not a certification scheme yet). Future verifiers (PASS, Aadhaar, …)
slot in as new method modules.

## Architecture
- **Hosting** (all in project `kunji-cc`): `issuer.kunji.cc` (`issuer-kunji-cc`, public flow `issuer-web/`),
  `admin.kunji.cc` (`admin-kunji-cc`, operator console `admin/`). Functions in codebase **`issuer`**
  (`issuer-functions/`, Node 20), isolated from the wallet's `app` codebase.
- **Origin/key:** `ISSUER_ORIGIN` (env, default the `.web.app` URL); signing-key SET in the secret
  **`KUNJI_ISSUER_SIGNING_KEY`** (rotation-capable — see `loadKeySet`). The `.well-known/kunji-issuer.json`
  publishes the public key set + brand.
- **Firestore (namespaced, deny-by-default, Admin-SDK only):** `verificationSessions`, `issuerOffers`,
  `issuerTokens`, `issuerCredentials` (ledger: type/idx/kid/booleans/issuedAt — **no PII**), `issuerStatusList`
  (per-type revocation), `issuerRateLimits`. **Storage** `verify-docs/**` (transient ID images; `storage.rules`
  deny ALL client access).
- **Endpoints** (`issuer-functions/index.js`, via `firebase.json` issuer rewrites): `/verify/start|upload|status`,
  `/.well-known/openid-credential-issuer|oauth-authorization-server|kunji-issuer.json`, `/credential-offer`,
  `/token`, `/credential`, `/status/{type}`. SD-JWT/OID4VCI core reused via byte-identical ports
  `issuer-functions/{vc.js,oid4vc.js,bbs.js,vcBbs.js}` (parity-guarded).

## Admin console (`admin.kunji.cc`)
Standalone Vite+React SPA (`admin/`), wallet-matched. **Auth = Google sign-in + the `admin:true` custom
claim** (being signed in is NOT enough — this project also mints anonymous wallet tokens; the claim is the
gate). One claim-gated Function `issuerAdminApi` at `admin.kunji.cc/api/*`: **review queue** (`/api/reviews`,
`/api/review/doc`, `/api/review/decision`), **ledger** + **revoke/un-revoke**, **stats**, read-only **keys**.
It holds **no signing secret** (keys read from the public `.well-known`) — it can review/revoke/read, never sign.

Grant an operator (one-time; they sign in once first so the account exists):
```
cd issuer-functions
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json node scripts/grant-admin.js you@example.com
```
Enable **Google** in Firebase Auth + add `admin-kunji-cc.web.app` (and the issuer domain) to Authorized domains.

## Key rotation (manual runbook)
`KUNJI_ISSUER_SIGNING_KEY` accepts a JSON **key set** `[{ "kid", "sk", "active" }]`. Rotate: generate a new
Ed25519 key, set the secret with the NEW key `active:true` + the previous key(s) retained (so unexpired
credentials still verify), redeploy `functions:issuer`. Prune a key only after every credential it signed has
expired. The admin "Signing keys" view shows the published kids.

## Deploy
```
firebase target:apply hosting issuer issuer-kunji-cc
firebase target:apply hosting admin  admin-kunji-cc
firebase functions:secrets:set KUNJI_ISSUER_SIGNING_KEY      # base64 Ed25519 secret (or a JSON key set)
npm --prefix issuer-web install && npm --prefix issuer-web run build   # → issuer-web/dist
npm --prefix admin install && npm --prefix admin run build             # → admin/dist (set admin/.env VITE_FIREBASE_*)
firebase deploy --only "functions:issuer,hosting:issuer,hosting:admin,storage,firestore:rules"
```
(`--force` the first v2 deploy to prune the removed `/idv/*` functions.) Leave `ISSUER_OPEN_MINT` unset
(dev-only). The orphaned `PERSONA_API_KEY`/`PERSONA_WEBHOOK_SECRET` Secret-Manager secrets can be deleted.

## Trust & compliance (non-engineering — gates go-live)
The engineering is the easy part. Document-review makes kunji a **data controller of ID images** (even
transiently): mitigated by deny-all Storage rules, admin-only streamed access, **deletion on decision** + a
daily sweep, and storing only booleans (S33). Go-live still needs: a GDPR/PIPA posture + retention policy +
privacy notice for the ID handling; a Firestore **TTL policy** on `verificationSessions`; the issuer Terms +
the relying-party trust basis (initially explicitly-pinned partners; certification/track record later); and
liability. See the plan + `docs/verified-credentials.md`.
