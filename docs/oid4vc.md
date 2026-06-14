# kunji ↔ OpenID4VC interop — design

**Status:** Implemented. The envelope lib (`src/lib/oid4vc.js`, with a byte-identical Node port in the
demos), the issuer-demo OpenID4VCI endpoints, the node-demo OpenID4VP verifier, a headless holder sim
(`oid4vc-sim.js`), and tests all ship and are proven end-to-end — **and the wallet UI is now wired**: a
user accepts an `openid-credential-offer://` in `CredentialsSheet` (paste/scan) and answers an
`openid4vp://` request via the scanner or a `?vp=` deep link → `PresentCredentialSheet`. Companion:
[`verified-credentials.md`](./verified-credentials.md) (the SD-JWT VC core) and [`scope.md`](./scope.md)
(the `vc:` request family this mirrors).

## 1. Why this is an envelope, not new crypto

kunji's credentials already **are** the interop format. `src/lib/vc.js` mints
`header{alg:EdDSA,typ:vc+sd-jwt,kid} . payload{iss,vct,iat,exp,cnf:{jwk},_sd_alg,_sd,status} ~disc~…~`
(IETF **SD-JWT VC**) and presents `…~<KB-JWT{typ:kb+jwt}{aud,nonce,iat,sd_hash}>` (the **Key-Binding
JWT**). So OpenID4VCI/VP interop is only the request/response **envelope** around the existing
`signJWS` / `buildPresentation` / `verifyCredentialPresentation` — `src/lib/oid4vc.js` wraps them and
never touches `vc.js` (the deterministic-derivation + parity invariants hold).

The load-bearing mapping is the holder key. The OID4VCI **proof-of-possession JWT** carries the holder
JWK that the issuer puts in the credential's `cnf.jwk`; the OID4VP **KB-JWT** is signed by that same
holder key. In the wallet both are `deriveCredentialHolderKey(masterKey, credential_issuer)` — so
holder-of-key, per-issuer separation, and unlinkability are exactly as in the native path.

## 2. Mapping table

| kunji concept | OpenID4VCI / OpenID4VP |
|---|---|
| per-issuer holder key (`deriveCredentialHolderKey(masterKey, iss)`) | proof JWT `jwk` **=** credential `cnf.jwk` **=** KB-JWT signer |
| issuer origin (`iss`, the `.well-known` trust anchor) | `credential_issuer` (VCI) / proof+KB `aud` is the issuer/verifier respectively |
| `buildPresentation({audience,nonce})` | the `vp_token`; `aud` = VP `client_id`, `nonce` = VP request `nonce` |
| `vc:<vct>[@iss]#claim,…` scope ([`scope.md`](./scope.md)) | a `presentation_definition` input_descriptor **or** a `dcql_query` (`pdToVcQuery`/`dcqlToVcQuery`/`requestQuery` map either → `{vct,disclose}`) |
| issuer `.well-known/kunji-issuer.json` (key by origin) | verifier `.well-known/kunji-verifier.json` — the HTTPS-anchored `client_id` scheme for signed requests (`verifyRequestObject`) |
| StatusList `status:{uri,idx}` + `checkStatus` | unchanged — the verifier polls the issuer's status endpoint |
| `verifyCredentialPresentation` | `verifyVpToken` wraps it, then enforces the query constraints (vct + each requested claim `=== true`) |

## 3. OpenID4VCI (issuance) — pre-authorized_code

```
holder ──GET  {issuer}/credential-offer──▶ { credential_offer: { credential_issuer, credential_configuration_ids, grants:{ pre-authorized_code } } }
holder ──POST {issuer}/token  { grant_type:…pre-authorized_code, pre-authorized_code }──▶ { access_token, c_nonce }
holder ──POST {issuer}/credential  Bearer access_token  { format:'vc+sd-jwt', proof:{ proof_type:'jwt', jwt:<openid4vci-proof+jwt> } }──▶ { credential: <SD-JWT VC> }
```

The proof JWT: header `{typ:'openid4vci-proof+jwt',alg:'EdDSA',jwk:<holder OKP>}`, claims
`{aud:credential_issuer, iat, nonce:c_nonce}`, signed by the holder key. The issuer verifies it
(`verifyProofJwt`) and mints the SD-JWT VC with `cnf.jwk = proof.jwk` via the existing `issue()`.
Issuer metadata is served at `/.well-known/openid-credential-issuer` (+ `/.well-known/oauth-authorization-server`
for the token endpoint). Lib: `parseCredentialOffer`, `buildProofJwt`, `verifyProofJwt`.

## 4. OpenID4VP (presentation) — direct_post, signed requests + DCQL

```
verifier ──GET /oid4vp/request──▶ openid4vp://?client_id=<origin>&request=<signed JWS>   (or the unsigned query-param form)
holder   verifies the request JWS against {client_id}/.well-known/kunji-verifier.json  (verifier authentication)
holder   builds vp_token = buildPresentation(sdjwt, disclose, aud=client_id, nonce)
holder   ──POST {response_uri}  { vp_token, [presentation_submission], state }──▶ verified locally → { approved, claims }
```

- **Signed requests (verifier authentication).** The request can be a **signed JWS** (JAR, request-by-value):
  header `{alg:'EdDSA',typ:'oauth-authz-req+jwt',kid}`, payload = the authz params. The verifier publishes
  its signing key at **`https://<client_id>/.well-known/kunji-verifier.json`** (the kunji HTTPS-anchored
  `client_id` scheme — `client_id` is the verifier's origin, mirroring the issuer-key model). The wallet
  fetches that key and verifies (`verifyRequestObject`), so the shown verifier is **cryptographically
  proven** to control its origin. An **unsigned** request still works but is shown as unverified and stays
  bound to its claimed `client_id` host (the S20 `responseTargetTrusted` check).
- **DCQL.** The request carries either a `presentation_definition` or a **`dcql_query`** (OpenID4VP 1.0).
  The DCQL response is a `vp_token` **object keyed by the credential id** (no `presentation_submission`);
  the PD response is the bare `vp_token` + a submission. `requestQuery`/`buildVpResponse` handle both.
- **`request_uri` by-reference.** Instead of embedding the whole signed JWS inline (a big QR), the verifier
  can serve it at a URL and the QR carries only `client_id` + `request_uri=<https url>`. The wallet
  `resolveAuthorizationRequest`s it: fetch (**HTTPS-only except loopback**) → the same `parseAuthorizationRequest`
  → the **same `verifyRequestObject` signature check**. The fetch host is **untrusted** — the request
  signature stays the trust anchor, so a forged `request_uri` body can't impersonate a verifier.
- **Encrypted response (`direct_post.jwt`).** When the (signed) request sets `response_mode: 'direct_post.jwt'`
  and publishes a P-256 **encryption** JWK in `client_metadata.jwks` (signature-protected — no extra fetch),
  the wallet JWE-encrypts the whole `buildVpResponse` body to that key and POSTs `{ response: <jwe>, state }`.
  An on-path observer / the transport can't read the `vp_token` (the presentation). The JWE is pinned to
  **`alg: ECDH-ES` + `enc: A256GCM`** (compact, ephemeral-static P-256 + Concat-KDF) — one algorithm, like
  the BBS ciphersuite (`src/lib/jwe.js`). Format-agnostic: it wraps SD-JWT and BBS vp_tokens alike.
- Lib: `parseAuthorizationRequest` (sets `signed`/`requestJwt`, parses either query form),
  `buildSignedAuthorizationRequest`, `verifyRequestObject`, `buildDcqlQuery`/`dcqlToVcQuery`/`requestQuery`,
  `buildVpToken`, `buildVpResponse`, `verifyVpToken`. The verifier resolves **issuer** keys from the
  credential's own `.well-known` and the **request** key from the *verifier's* `.well-known` — **no kunji
  server in the path**; KB-JWT `aud`/`nonce` are checked against the request, exactly like the login path.

## 5. Scope & pinned shapes

Implemented: the **pre-authorized_code** grant (VCI); **direct_post** (VP) with **both**
`presentation_definition` and **DCQL**, and **both** unsigned and **signed (JAR)** requests — a signed
request is verified against the verifier's `.well-known` key (the **HTTPS-anchored `client_id` scheme**);
SD-JWT VC (EdDSA) **and `vc+bbs`** (the unlinkable v3 credential — verified-credentials.md §7). A DCQL
query carries `format: 'vc+bbs'`; the holder answers with `buildBbsVpToken` and the verifier's
`verifyVpToken` **dispatches by format**. A BBS `vp_token` is a **tagged string** `bbs~<base64url(JSON)>`
(not a nested object) — so it rides the existing string-typed `vp_token`/`vc_presentations` slots and the
login assertion's canonical-JSON signing is undisturbed; verifiers dispatch on the `bbs~` tag, resolving
the issuer's BBS key from its `.well-known` (`alg:'BBS'`). BBS uses DCQL (not presentation_definition).
Also implemented: **`request_uri` by-reference** (the verifier serves the signed request at a URL; the
wallet fetches HTTPS-only then verifies the signature as usual — the fetch host is untrusted) and the
**encrypted response** `response_mode: 'direct_post.jwt'` (the wallet JWE-encrypts the `vp_token` to the
verifier's published P-256 enc key — **`ECDH-ES`/`A256GCM`**, one pinned algorithm, `src/lib/jwe.js`).

Also implemented (this slice):

- **`dc+sd-jwt` format alignment.** The SD-JWT VC format/`typ` is migrating `vc+sd-jwt` → `dc+sd-jwt`
  (OpenID4VC drafts + EU ARF). kunji **accepts both** forever (`vc.js` verify + the `oid4vc.js`
  `SD_JWT_VC_FORMATS` accept-list); the default **emit** stays `vc+sd-jwt` so existing credentials + mint
  bytes are byte-stable. A demo can mint/request `dc+sd-jwt` to prove interop (`oid4vc-sim --dc-sd-jwt`).
- **DPoP (RFC 9449).** A sender-constrained access token on the OID4VCI token+credential leg, **opt-in**:
  the wallet presents a `dpop+jwt` proof at `/token`; if the issuer echoes `token_type:'DPoP'` it binds the
  token to the proof key (`cnf.jkt`) and `/credential` requires a matching proof (`jkt` + `ath`). No DPoP
  header ⇒ the legacy bearer path, byte-unchanged. **EdDSA-pinned** (kunji's one curve — a deliberate
  deviation from the RFC's usual ES256). `buildDpopProof`/`verifyDpopProof`/`jwkThumbprint` in `oid4vc.js`.
- **`authorization_code` grant + PKCE (S256).** A second issuance path alongside pre-authorized_code (the
  default). The lib (`generatePkce`/`buildAuthorizationRequest`/`resolveAuthorizationEndpoint`/`verifyPkce`),
  the issuer demo (`/authorize` → single-use `code` storing only the `code_challenge`; `/token` re-checks
  `redirect_uri` + verifies the verifier), and the headless sim (`oid4vc-sim --auth-code`) prove it
  end-to-end. **The wallet UI is deferred**: kunji is a QR/no-redirect wallet, so there is no
  authorization-server redirect or custom-scheme return — a pasted authorization_code-only offer fails with
  a precise message. A same-device `?code=` deep-link on-ramp is a documented future slice.
- **x509 / DID `client_id` schemes.** OpenID4VP verifier auth beyond the HTTPS-anchored `.well-known`
  scheme (which stays the default). `verifyRequestObject` dispatches on the `client_id` prefix
  (`parseClientIdScheme`): `did:jwk` (key embedded — no fetch), `did:web` (key from
  `https://<host>/.well-known/did.json`), and `x509_san_dns:<dns>` (an ES256 JWS carrying an `x5c` chain).
  DID/x509 verifiers are **injected** into `verifyRequestObject` (`resolveDidKey` / `verifyX509`) so the
  envelope stays EdDSA-pure and free of the DER parser (`src/lib/did.js`, `src/lib/x509.js`).

  **x509_san_dns SECURITY BOUNDARY (scoped — a client-only wallet can't run a CA program).** `verifyX5cChain`
  verifies: the leaf SAN dNSName == `client_id`, the leaf validity window, each link's **ECDSA-P256-SHA256**
  signature, and that the chain terminates at a **pinned trust-anchor set (empty ⇒ fail closed)** — ES256
  only. It does **NOT** do full RFC 5280 path validation (BasicConstraints/KeyUsage/EKU/name-constraints/
  policy), revocation (CRL/OCSP), RSA / non-P256 certs, or wildcard SANs. `@peculiar/x509` is the heavy-dep
  fallback only if a future mandate needs full path validation. The shipped wallet pins **no anchors**, so
  `x509_san_dns` fails closed until a deployment configures `WALLET_TRUST_ANCHORS`; `did:web`/`did:jwk` work.
  `did:jwk` has **no origin binding**, so the S20 response-target guard requires an **encrypted response**
  (`direct_post.jwt`) for it. Runtime E2E: `oid4vc-sim --scheme=did:jwk`; x509 + did:web are unit-test-proven
  (`tests/oid4vc.{x509,did}.test.js` drive the real `verifyRequestObject` + `x509.js`/`did.js`).

Deferred (documented, not built): the **encrypted *request*** (verifier→wallet) — deliberately out of
scope: it would require the verifier to know the wallet's key before the QR is shown, infeasible for a fresh
QR scan in a no-directory wallet, whereas the response carries the sensitive data so encrypting *it* is the
meaningful, feasible privacy win — and the `authorization_code` **wallet UI** (lib+demos+sim only). These
are all envelope-only extensions — none touches the SD-JWT VC core.

## 6. Where it lives

- `src/lib/oid4vc.js` — the canonical envelope (wraps `vc.js` + the `capability.js` JWS primitives);
  byte-identical Node port in `examples/kunji-node-demo/oid4vc.js` + `examples/kunji-issuer-demo/oid4vc.js`
  (parity-guarded by `tests/oid4vc.parity.test.js`, like `vc.js`). `resolveAuthorizationRequest` (fetch a
  `request_uri`, HTTPS-only) lives here too.
- `src/lib/jwe.js` — the minimal `ECDH-ES`/`A256GCM` JWE (compact) for the encrypted response;
  `encryptJwe`/`decryptJwe`/`generateJweKeyPair`, isomorphic over `crypto.subtle` (no new dep).
  Byte-identical Node port `examples/kunji-node-demo/jwe.js` (parity-guarded by `tests/jwe.test.js`).
- Issuer: `examples/kunji-issuer-demo/oid4vci.js` (offer/token/credential store) + the routes in its `server.js`.
- Verifier: the `/oid4vp/{request,response,result}` routes + `GET /.well-known/kunji-verifier.json` and the
  persisted `.verifier-key` (request signing) in `examples/kunji-node-demo/server.js`. `/oid4vp/request`
  emits a signed request + DCQL by default (`?signed=0`, `?query=pd` toggle the legacy/interop matrix;
  `?ref=1` returns a `request_uri` served by `GET /oid4vp/request-object/{id}`; `?enc=1` sets
  `direct_post.jwt` + publishes the verifier's P-256 enc key in `client_metadata`). The enc keypair is
  persisted beside the signing key as `.verifier-enc-key`; `/oid4vp/response` `decryptJwe`s a `{response}` body.
- Holder sim: `examples/kunji-node-demo/oid4vc-sim.js` (`npm run oid4vc`) — offer→token→credential, then a
  signed+DCQL request (verified, forgery-rejected) → vp_token → direct_post; `--legacy` runs unsigned+PD,
  `--ref` drives the `request_uri` fetch, `--enc` drives the encrypted response.
- **Wallet:** `src/services/credentials.js` `receiveViaOffer` (OpenID4VCI redeem → store), `presentViaOid4vp`
  (`buildVpResponse` — DCQL keyed vs PD), and `fetchVerifierKeys` (the verifier's `.well-known`);
  `CredentialsSheet.jsx` accepts an offer (paste/scan); `PresentCredentialSheet.jsx` is the consent sheet
  (default-deny + linkability caveat + a **"Verified verifier"** badge when the request signature checks
  out), opened from `Dashboard.handleQRScan` (which calls `verifyRequestObject` on a signed request) on an
  `openid4vp://` scan or the `?vp=` deep link (`src/App.jsx`). This **closes the S20 "verifier identity
  unverified" caveat** for signed requests; unsigned requests stay host-bound + flagged.
- The kunji-native `POST /issue` and the login-QR `vc_presentations` paths are **unchanged** (interop is additive).
