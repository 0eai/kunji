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
should **pre-bake predicates**: instead of `dob: 2001-04-05`, issue `age_over_18: true` (and
`age_over_21`, etc.) so disclosing the predicate reveals the *answer*, not the DOB. This gives the
common "prove you're over 18" use case with **plain SD-JWT and no ZK**.

## 7. Unlinkability — honest trade-offs

A reused credential is inherently a correlation handle (the issuer signature + claim values are
identical across presentations). This is in tension with kunji's per-app unlinkability, so make it a
**conscious, tiered** choice:

| Tier | Mechanism | Unlinkability | Cost |
|---|---|---|---|
| **v1** | SD-JWT + per-issuer holder key + **predicate pre-baking** + audience-bound KB-JWT | Linkable across **colluding** RPs (same issuer sig); minimal PII | none beyond Ed25519 (reuses today's crypto) |
| **v2** | **Batch / one-time-use** credentials (issuer mints N single-use SD-JWTs) | Presentations don't share a signature | issuer-side issuance volume |
| **v3** | **BBS+** signatures (derive an unlinkable proof per presentation + predicate proofs) | True unlinkable selective disclosure | new dep: BLS12-381 pairings (`@noble/curves` has it) — a real lift |

**Recommendation:** ship **v1**; the wallet **explicitly warns** at consent that a verified
credential is more linkable than the default per-app `sub` (a §9.2-style caveat). Move to v2/v3 only
if the privacy bar demands it.

## 8. Issuance

Two interoperating paths:

- **kunji-native relay (mirrors the agent capability relay):** the issuer shows an **offer** (QR /
  6-digit code / link) describing `{ iss, vct, claims preview, nonce }`; the user accepts in the
  wallet; the wallet sends the **holder public key** (`deriveCredentialHolderKey`) so the issued VC
  binds to it; the issuer mints the SD-JWT and **ECDH-delivers** it through a short-TTL
  `credentialSessions/{id}` relay (the same shape as `agentSessions` + `agentCapabilityPoll`); the
  wallet decrypts and stores it.
- **OpenID4VCI** for real-world issuers (credential offer → token → credential endpoint). Recommended
  for production issuers; the native relay is the zero-infra demo path.

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
2. **Wallet integration (Phase 3).** `CredentialsSheet` (receive/list/revoke), `kind:'credential'`
   vault storage (`vaultWrite` + `firestore.rules`), the `credentialSessions` issuance relay +
   `credentialPoll` function, the `ApprovalModal` VC consent toggles + linkability warning, and
   wiring presentation into the real `submitDiscoverableAssertion` (so a user holds + presents in the
   app); mirror the RP verifier into the Firebase login/agent demos.
3. **Interop.** OpenID4VCI/VP issuance & presentation.
4. **Unlinkability.** Batch/one-time credentials → BBS+ if warranted.

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
