# kunji verified credentials — design

**Status:** Phase 2 implemented (protocol + issuer + RP, headless) — the credential lib
(`src/lib/vc.js`, with a Node port in the demos), `deriveCredentialHolderKey`, SD-JWT VC
mint/present/verify, `.well-known` issuer discovery, predicate pre-baking, KB-JWT holder binding, and
StatusList revocation all ship and are proven end-to-end via sims (`examples/kunji-issuer-demo` +
`kunji-node-demo`). **Wallet integration (UI/storage/issuance relay) is Phase 3** — see §14. Before
this, everything a kunji user shared was **self-asserted**: the per-app key signs `claims`, and the
RP must treat them as untrusted (`discoverable-login.md` §6.8). Verified credentials add a **third-party issuer** whose signature the
RP trusts — verifiable **with no kunji backend in the path** (the §6 trust model, different signer).
Companion docs: [`scope.md`](./scope.md) (the `vc:` request family) and
[`push-relay.md`](./push-relay.md) (a connected app asking for a credential later).

## 1. Goals & non-goals

**Goals**

- Let a trusted **issuer** (a university, employer, age-verification provider, government wallet)
  sign an attestation about a user; let the user **present** it to any RP with **selective
  disclosure**, verifiable **without kunji in the path**.
- Preserve kunji's invariants: per-app unlinkability for the default identity, holder-of-key (a
  credential isn't a bearer token to steal), human consent on every disclosure, no kunji backend in
  the verify path, anonymous wallet.
- Interoperate with the broader ecosystem (OpenID4VC / EUDI), not a kunji-proprietary blob.

**Non-goal (explicit, carried over from `discoverable-login.md` §12):** RP-requested **self-asserted**
typed attributes — an app asking the user to *type* a DOB / student id at approval. Unverified data
typed into kunji is no more trustworthy than the same field in the RP's own form and pushes PII into a
zero-knowledge wallet for no assurance gain. Only **issuer-signed** claims count as "verified."

## 2. Roles & trust

| Role | Who | Holds / does |
|---|---|---|
| **Issuer** | a domain (`issuer.example`) | Signs credentials with an issuer key; publishes its keys + a revocation status list over HTTPS. |
| **Holder** | the kunji wallet | Receives credentials, stores them encrypted in the vault, presents them under holder-of-key with selective disclosure. |
| **Verifier (RP)** | the relying app | Discovers/pins the issuer key, verifies the presentation **locally**. |

**The trust shift:** the RP no longer trusts only "the same key returned" (self-sovereign login) — it
now also trusts a **named issuer** for specific claims. That trust is anchored in the **issuer's
HTTPS domain** (§5), *not* in kunji. kunji vends nothing here; it only transports and holds.

## 3. Format — SD-JWT VC

Adopt **SD-JWT VC** (IETF `oauth-sd-jwt-vc`) rather than a kunji-specific format:

- It **is** a JWS, so it reuses the exact primitives in `src/lib/capability.js`: the EdDSA compact
  signer (`signJWS`/`verifyJWS`), the OKP-Ed25519 JWK helpers, and `cnf` (RFC 7800) holder binding.
- **Selective disclosure** is built in (no ZK needed): the issuer signs `_sd: [hash(disclosure)…]`;
  the holder reveals only the salted disclosures it chooses; the RP recomputes the hashes.
- **Holder binding** via `cnf` — the same field the capability already uses; presentation proof is a
  **Key-Binding JWT**, mechanically identical to `buildAgentProof`.
- Interop: SD-JWT VC + OpenID4VCI/VP is the path most issuers/wallets are standardizing on.

Issued credential (conceptual):

```jsonc
// header
{ "alg": "EdDSA", "typ": "vc+sd-jwt", "kid": "issuer-2026-01" }
// payload (issuer-signed)
{
  "iss": "https://issuer.example",
  "vct": "https://issuer.example/credentials/age",   // credential type
  "iat": 1750000000,
  "exp": 1781536000,
  "cnf": { "jwk": { "kty":"OKP","crv":"Ed25519","x":"<holder pub>" } },
  "_sd_alg": "sha-256",
  "_sd": ["<hash of disclosure 1>", "<hash of disclosure 2>", "…"],
  "status": { "uri": "https://issuer.example/status/7", "idx": 1234 }
}
// + disclosures, each = base64url(JSON [ "<salt>", "<claim>", <value> ]):
//   ["a1b2…","age_over_18", true]
//   ["c3d4…","name","Ada Lovelace"]
```

Wire format (SD-JWT): `<issuer-JWS>~<disclosure1>~<disclosure2>~…` ; a **presentation** appends a
Key-Binding JWT: `…~<disclosure_selected>~<KB-JWT>`.

## 4. Issuer identity & key discovery

An issuer is a domain; it publishes its keys over HTTPS (DID:web-equivalent, no new infra — HTTPS is
the trust anchor):

```
GET https://issuer.example/.well-known/kunji-issuer.json
{
  "issuer": "https://issuer.example",
  "name": "Issuer Example",
  "keys": [ { "kid":"issuer-2026-01", "kty":"OKP", "crv":"Ed25519", "x":"<base64url>" } ]
}
```

The RP fetches this from the credential's `iss`, matches the `kid`, **caches with a TTL, and pins**.
Rotation = publish multiple keys + bump `kid`. (A DID:web alias can be layered on later for ecosystem
interop; the `.well-known` doc is the minimum.)

## 5. Holder binding & the key-separation invariant

The credential binds to a **kunji holder key** via `cnf`, so a stolen credential is useless without
the holder's private key. Add a derivation parallel to the existing ones (`AGENTS.md` "Key
separation"):

```
deriveAppKeyPair(masterKey, domain)  : HKDF salt="kunji-app-key-v1"  info="kunji-app:"+domain   (today)
deriveVaultId(masterKey)             : HKDF salt="kunji-vault-id-v1"  info="kunji-vault-id"       (today)
deriveCredentialHolderKey(masterKey, issuer)
                                     : HKDF salt="kunji-cred-holder-v1" info="kunji-cred-holder:"+issuer   (new)
```

**Per-issuer** holder keys (not one global key) limit the cross-RP correlation surface to "one holder
key per issuer." The new derivation is purely additive — the existing byte-stable derivations are
untouched (the deterministic-derivation invariant holds).

## 6. Selective disclosure & predicates

SD-JWT lets the holder reveal a **subset** of claims. To avoid leaking the underlying value, issuers
**pre-bake predicates**: instead of `dob: 2001-04-05`, one **age** credential carries a boolean for
each threshold — `age_over_13`, `age_over_16`, `age_over_18`, `age_over_21` — each its own
disclosure. The issuer computes them from the DOB at issuance; **the DOB itself is never in the
credential**. An RP requests the bar it needs and the holder reveals only that one, so proving "16+"
leaks neither the birthday nor the other thresholds — plain SD-JWT, no ZK.

An RP selects the threshold with the scope's claim selector (see [`scope.md`](./scope.md)):
`vc:age#age_over_16`, or `vc:age@https://issuer#age_over_16` to pin the issuer. The holder discloses
`age_over_16`; the RP **requires it to be `true`** — a disclosed `false` (an under-age holder) is
rejected at the policy step (§9). Reference: `examples/kunji-issuer-demo` bakes the thresholds and
`kunji-node-demo` (`REQUIRE_VC=vc:age#age_over_18`) enforces them.

## 7. Unlinkability — honest trade-offs

A reused credential is inherently a correlation handle (the issuer signature + claim values are
identical across presentations). This is in tension with kunji's per-app unlinkability, so make it a
**conscious, tiered** choice:

| Tier | Mechanism | Unlinkability | Cost | Status |
|---|---|---|---|---|
| **v1** | SD-JWT + per-issuer holder key + **predicate pre-baking** + audience-bound KB-JWT | Linkable across **colluding** RPs (same issuer sig); minimal PII | none beyond Ed25519 (reuses today's crypto) | shipped |
| **v2** | **Batch / one-time-use** credentials (issuer mints N single-use SD-JWTs) | Presentations share no correlation handle | issuer-side issuance volume | **shipped** |
| **v3** | **BBS** signatures (derive a fresh randomized proof per presentation) | True unlinkable selective disclosure from ONE credential | dep: `@digitalbazaar/bbs-signatures` (pure JS over `@noble/curves`) | **shipped (foundation)** |

**v2 — how it works (shipped).** A correlation handle is more than the issuer signature: the holder key
`cnf.jwk` lives in the issuer-signed payload and is revealed at **every** presentation, so distinct
signatures alone don't unlink — **each one-time copy must also bind a distinct holder key**. So on
receive the wallet generates **N random holder keys**, asks the issuer for **N copies** (one per key:
native `/issue { holderJwks:[…] }` or OpenID4VCI `proofs:{jwt:[…]}`), and stores each copy with its own
random holder secret (`holderSk`) under one `poolId`. Each presentation **spends** a fresh copy
(present-then-delete), so no two presentations share an issuer signature, a holder key, or a StatusList
index. The issuer must also **coarsen `iat`/`exp`** (the demo rounds to the UTC-day boundary): the
issuer payload is revealed at every presentation, so a per-second timestamp shared across a batch would
itself be a correlation handle — coarsening collapses every same-day issuance into one large anonymity
set. Batch is **opt-in by graceful fallback**: an issuer that returns a single credential yields a
reusable v1 credential, and pre-v2 stored credentials still present (the holder key is re-derived when
no `holderSk` is stored). Residual, surfaced at consent: identical **claim values** still match across
presentations — predicate pre-baking (`age_over_18:true`) keeps that non-identifying. Reference
implementation: `src/services/credentials.js` (`receiveFromIssuer`/`receiveViaOffer`/`groupByPool`/
`selectForPresentation`/`spendIfOneTime`), the issuer demo `issueBatch`, and the runnable proof
`examples/kunji-node-demo/unlinkable-sim.js` (`npm run unlinkable`).

**v3 — how it works (foundation shipped).** BBS signs a VECTOR of messages (one per claim, plus an
always-revealed `header` of `{iss, vct, exp}`) with one short signature; the holder derives a fresh,
**randomized** zero-knowledge proof that reveals only a chosen subset and binds to a presentation header
(`{aud, nonce}`). Two presentations of the **same** credential share **no** bytes/handle — no signature,
no holder key — so they're unlinkable from **ONE** credential (v2 needed N copies). The header's `exp` is
coarsened to the UTC day (the same anonymity-set reasoning as v2). Library: `@digitalbazaar/bbs-signatures`
(pure JS over `@noble/curves` — no WASM, isomorphic). Modules: `src/lib/bbs.js` (primitive wrapper) +
`src/lib/vcBbs.js` (`mintBbsCredential`/`buildBbsPresentation`/`verifyBbsPresentation`) — **parallel to
the SD-JWT core, which is untouched**; byte-identical Node ports in the demos. Issuer: `issueBbs` + the
BBS key in `/.well-known`; wallet: `receiveBbsFromIssuer` + a `format:'bbs'` record + the
"unlinkable (BBS)" receive toggle in `CredentialsSheet`; runnable proof
`examples/kunji-node-demo/bbs-sim.js` (`npm run bbs`) — one credential → two unlinkable proofs.
**Present over OID4VP + login (shipped).** A BBS credential presents over the **same envelopes** as
SD-JWT: an OpenID4VP `vc+bbs` DCQL request → `buildBbsVpToken` → `verifyVpToken` (which **dispatches by
format**), and the discoverable-login assertion (`vc_presentations`). On the wire a BBS presentation is a
**tagged string** (`bbs~<base64url(JSON)>`) so every envelope stays string-typed and the assertion's
canonical-JSON signing is undisturbed; verifiers dispatch on the `bbs~` tag. The wallet's
`presentViaOid4vp` + login `handleApprove` branch on `cred.format`; an OID4VP request offers a BBS
credential only when it asks `vc+bbs`, and login prefers SD-JWT when both formats satisfy the request
(generic-RP compatibility — login-protocol format negotiation is a follow-on). All three demo RPs
(`kunji-{login,node}-demo`) verify both formats.

**Holder binding (shipped).** A BBS credential is **non-transferable**: the issuer signs a high-entropy
holder secret as an extra, **always-undisclosed** message; the secret is **derived from the master key**
(`deriveBbsHolderSecret(masterKey, issuer)`) and **never stored in the blob** — the holder re-derives it
to present. BBS proof generation needs *every* message value, so a leaked credential blob without the
master key can't produce a verifying proof (a stolen-blob "thief" presentation is rejected). The verifier
is **unchanged** — the secret is just one more undisclosed message the proof already commits to (never
revealed), so unlinkability is preserved. Opt-in per credential (a `holderBound` flag); pre-binding blobs
still present unbound. **Residual (documented):** the issuer *sees* the secret at issuance (it signs it
via the public `sign`), so a malicious issuer could impersonate the holder — bounded (issuer trust is
already assumed; cross-presentation unlinkability is unaffected; it protects against third-party blob
theft). Closing the issuer-impersonation gap needs **blind issuance** (the issuer signs a commitment it
can't see), a future hardening — **deferred, blocked on the dependency.**

> **Blind issuance (deferred — tracked).** Design when unblocked: the wallet commits to
> `deriveBbsHolderSecret(masterKey, issuer)` (a commitment + proof-of-knowledge — the secret is never
> sent); the issuer **blind-signs** the claims + the commitment (`BlindSign`); the wallet **unblinds** to
> a normal BBS credential it presents with the holder secret undisclosed (re-derived from the master key)
> **exactly as today** — no change to `buildBbsPresentation`/`verifyBbsPresentation` or the presentation
> path. Net effect over the shipped holder binding: the issuer never sees the secret, so it can't
> impersonate (closes S28). **Blocker:** `@digitalbazaar/bbs-signatures` (3.1.0, latest) ships the blind
> code in `lib/bbs/blind/` but its `exports` map exposes only `lib/index.js` — no released version exports
> `BlindSign`/`BlindProofGen`/… and deep imports are hard-blocked. **Unblock condition:** the lib exports
> the blind API (or blind BBS reaches a CFRG WG draft — it's currently the individual `draft-kalos-bbs-
> blind-signatures`). Then this is a **small slice over the public API**. Until then S28 stays a
> documented, accepted Low (issuer trust is already assumed; third-party blob theft is already closed by
> the shipped holder binding).

**Recommendation:** **v1 + v2 shipped, v3 foundation shipped** (the wallet still warns at consent that a
verified credential is more identifiable than the default per-app `sub`, a §9.2-style caveat). **v3 is
complete** — unlinkable, presentable over OID4VP + login, and **holder-bound (non-transferable)**. The
only remaining BBS work is optional future hardening — **blind issuance** (closes S28) + per-verifier
pseudonyms — both **deferred, blocked on the lib exporting the blind API** (see the tracked note above).

### 7.1 Personhood / `verified_human` — issuer-side uniqueness, NOT per-app dedup

The `verified_human` credential (issuer.kunji.cc; see `docs/issuer.md`) attests `is_human: true` and is made
**unique per real government ID** by an **issuer-side nullifier** (a non-rotating, secret-keyed one-way
scrypt digest of the normalized ID, recorded in the deny-all `issuerNullifiers` — never in the credential).
This raises the **Sybil cost floor** to "acquire N distinct real IDs". It deliberately does **NOT** give a
relying party **per-app dedup** ("one account per human"): because credentials present **unlinkably** (v2/v3),
an RP only ever learns *"holds a verified-human credential"*, not whether two presentations are the same
person. Per-app dedup needs a **per-verifier pseudonym** (a stable-per-RP, unlinkable-across-RPs value derived
from the credential) — that is **roadmap 4.1**, the same deferred BBS work as above. The nullifier must
**never** enter the credential: a stable value an RP sees would become a colluding-RP global identifier,
breaking per-app unlinkability. Caveats: uniqueness is bound by **operator transcription accuracy** ("one per
*correctly-transcribed* ID"); one human holding two ID documents enrolls twice → two credentials (a coarse
signal, by design).

## 8. Issuance

Two interoperating paths:

- **kunji-native (shipped).** *Synchronous:* the wallet derives the **holder key**
  (`deriveCredentialHolderKey`) and POSTs `{ holderJwk }` to the issuer's `/issue`, which mints the
  SD-JWT bound to it and returns it. *Async:* the wallet leaves a transport key + 64-hex `sessionId`;
  the issuer ECDH-encrypts the SD-JWT and deposits it via `credentialOfferRelay`; the wallet polls
  `credentialPoll` (`credentialSessions/{id}`, the same shape as `agentSessions`/`agentCapabilityPoll`)
  and decrypts. See `src/services/credentials.js` `receiveFromIssuer`/`receiveViaRelay`.
- **OpenID4VCI** for real-world issuers (credential offer → token → credential endpoint, with a holder
  proof JWT). Implemented headless (issuer-demo endpoints + the envelope lib + sim — see
  [`oid4vc.md`](./oid4vc.md)); recommended for production issuers, with the native relay as the zero-infra
  demo path. Presentation has the matching **OpenID4VP** envelope (direct_post + presentation_definition).

**Storage:** encrypted in the vault via a new `vaultWrite` `kind: 'credential'` (joining
`profile|activity|agent|device` in `functions/index.js`) → `vaults/{vaultId}/credentials/{credId}`,
holding the ciphertext SD-JWT + non-sensitive metadata (`vct`, `iss`, `exp`) for listing.

## 9. Presentation & verification (backendless)

An RP requests a credential through **scope** (`scope:["vc:age_over_18"]` or
`vc:age_over_18@issuer.example`, see [`scope.md`](./scope.md)). The wallet finds a matching
credential, lets the user consent, and presents `SD-JWT + selected disclosures + KB-JWT`. The KB-JWT
is `buildAgentProof`-shaped:

```jsonc
{ "typ":"kb+jwt", "alg":"EdDSA" }
{ "aud":"example.com", "nonce":"<RP challenge>", "iat":1750000000, "sd_hash":"<hash of presented SD-JWT>" }
// signed by the credential's cnf (holder) key
```

The RP verifies **locally** (no kunji server), shipped in the shared verifier lib for parity:

1. **Issuer signature** — verify the SD-JWT JWS against the issuer key discovered at `iss` (match `kid`, §4).
2. **Disclosures** — recompute each presented disclosure's hash; confirm `∈ _sd`; reconstruct the claims.
3. **Holder binding** — KB-JWT verifies against `cnf.jwk`; `aud == RP`, `nonce == challenge`,
   `sd_hash` matches, `iat` fresh (±2 min) — identical to the agent-proof check.
4. **Validity** — `exp` not passed; **status** not revoked (§10).
5. **Policy** — `vct` is acceptable; the disclosed claims satisfy the requested predicate/scope.

No kunji backend, exactly like §6 / `verifyCapabilityAssertion`.

## 10. Revocation

Issuer-hosted **Status List** (a signed bitstring at a URL; the credential carries `status:{uri,idx}`).
Cacheable, scales to millions, and leaks no per-credential lookup. The existing issuer-signed
`revocations/{id}` pattern (`firestore.rules`) is the low-volume fallback.

## 11. Wallet UX

A new **Credentials** area:

- **Receive** — scan an issuer offer → review `{ issuer, type, claims }` → consent → store encrypted.
- **List/manage** — see held credentials, expiry, revoke/delete.
- **Present at login/consent** — when a login QR or capability request carries a `vc:*` scope, the
  approval sheet shows *"example.com wants to verify: **you're over 18** (from issuer.example)"* with
  a **default-off** per-credential toggle (the same shape as today's profile-share toggle) and the
  linkability caveat (§7).

## 12. Security & privacy considerations

- **Trust the issuer, not kunji.** kunji neither vouches for issuers nor sees the claims; the RP's
  trust decision is "do I accept `issuer.example` for `vct`?".
- **Linkability.** Verified attributes are more linkable than the default `sub`; surface this at
  consent (§7). Per-issuer holder keys + audience-bound presentations bound the damage.
- **No server-fetch of issuer-controlled URLs by the RP beyond key/status discovery**, and pin those
  (avoid SSRF/tracking — same spirit as the `claims.picture` rule in §6.8).
- **Holder-of-key** prevents credential theft/replay; **human consent** gates every disclosure.

## 13. Invariants preserved

No kunji backend in issuance-verification or login path; the default per-app `sub` unlinkability is
untouched (VCs are opt-in, consented, with an explicit warning); deterministic derivations stay
byte-stable (the holder key is additive); the wallet stays anonymous.

## 14. Phasing

1. **Protocol + issuer + RP (Phase 2 — done, headless).** SD-JWT VC, `deriveCredentialHolderKey`,
   `.well-known` issuer discovery, predicate pre-baking, KB-JWT presentation, StatusList revocation,
   the RP-side verifier + `vc:` presentation, the `kunji-issuer-demo`, and Node holder/RP sims +
   tests. Proven end-to-end without a wallet UI.
2. **Wallet integration (Phase 3 — done).** `CredentialsSheet` (receive/list/delete),
   `kind:'credential'` vault storage (`vaultWrite` + `firestore.rules`), the `credentialSessions`
   issuance relay (`credentialOfferRelay` deposit + `credentialPoll`), the `ApprovalModal` VC consent
   toggles + linkability warning, presentation wiring in `submitDiscoverableAssertion`
   (`src/services/credentials.js`), and the RP verifier mirrored into the Firebase demo
   (`kunji-login-demo` `kunjiCallback`). A user holds + presents a credential in the app.
3. **Interop (done, headless).** OpenID4VCI issuance + OpenID4VP presentation as a thin envelope over
   the SD-JWT VC core — `src/lib/oid4vc.js` (+ Node port), the issuer-demo OpenID4VCI endpoints, the
   node-demo OpenID4VP verifier, a headless holder sim, and tests. Wallet-UI wiring is the follow-on.
   See [`oid4vc.md`](./oid4vc.md).
4. **Unlinkability — v2 (done).** Batch / one-time-use credentials: the issuer mints N single-use
   SD-JWTs, each bound to a distinct random holder key; the wallet spends one per presentation, so
   presentations share no correlation handle (signature, holder key, or status idx). Graceful fallback
   to a reusable v1 credential for non-batch issuers; pre-v2 credentials still present. See §7 + the
   `npm run unlinkable` sim.
5. **Unlinkability — v3 (done: foundation + present-over-OID4VP/login).** BBS signatures: ONE credential
   derives a fresh randomized ZK proof per presentation (no copies), revealing only a chosen subset, bound
   to (aud, nonce). Modules `src/lib/bbs.js` + `src/lib/vcBbs.js` (parallel to the SD-JWT core),
   `@digitalbazaar/bbs-signatures`, the issuer-demo `issueBbs` + BBS `.well-known` key, the wallet
   receive/list/**present** (`format:'bbs'` record; present over OpenID4VP `vc+bbs` + the login assertion
   via a `bbs~` tagged-string), all three demo RPs verifying both formats, and `npm run bbs` /
   `wallet-sim --bbs`. **Holder binding (done):** non-transferable via an undisclosed,
   master-key-derived holder secret (`deriveBbsHolderSecret`, signed but never stored; re-derived to
   present) — a stolen blob without the master key can't present. **Deferred (future hardening):** blind
   issuance (issuer can't see the secret → can't impersonate) + per-verifier pseudonyms. See §7.

## 15. Open decisions

- Format: **SD-JWT VC** (recommended) vs full W3C VC-Data-Integrity.
- Unlinkability stance: **linkable v1 + predicate-baked** (recommended) vs commit to BBS+ early.
- Issuer discovery: **`.well-known`** (recommended) vs DID methods.
- Holder-key scoping: **per-issuer** (recommended) vs per-credential-type vs one global key.
- Interop surface: adopt OpenID4VC now vs after the native MVP.

## 16. Where it will live (when built)

- VC mint/verify + KB-JWT + `scopeSatisfies` for `vc:*` → the shared verifier lib (`src/lib/`,
  mirrored in `examples/*/`), parity tests in `tests/`.
- `deriveCredentialHolderKey` → `src/lib/crypto/` (new HKDF derivation, key separation).
- Storage → `vaultWrite` `kind:'credential'` (`functions/index.js`) + `firestore.rules`.
- Issuance relay → a `credentialSessions` function mirroring `agentCapabilityPoll`/`agentRequestRelay`.
- Wallet UI → a `CredentialsSheet.jsx` + hooks in the login/agent approval sheets.
