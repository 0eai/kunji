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
Deferred (documented, not built): the `authorization_code` grant + PKCE, DPoP,
`request_uri` by-reference, **x509/DID `client_id` schemes**, encrypted requests, and the in-flight
`vc+sd-jwt` → `dc+sd-jwt` format rename (kept as the `SD_JWT_VC_FORMAT` knob in `oid4vc.js`). These are
envelope-only extensions — none touches the SD-JWT VC core.

## 6. Where it lives

- `src/lib/oid4vc.js` — the canonical envelope (wraps `vc.js` + the `capability.js` JWS primitives);
  byte-identical Node port in `examples/kunji-node-demo/oid4vc.js` + `examples/kunji-issuer-demo/oid4vc.js`
  (parity-guarded by `tests/oid4vc.parity.test.js`, like `vc.js`).
- Issuer: `examples/kunji-issuer-demo/oid4vci.js` (offer/token/credential store) + the routes in its `server.js`.
- Verifier: the `/oid4vp/{request,response,result}` routes + `GET /.well-known/kunji-verifier.json` and the
  persisted `.verifier-key` (request signing) in `examples/kunji-node-demo/server.js`. `/oid4vp/request`
  emits a signed request + DCQL by default (`?signed=0`, `?query=pd` toggle the legacy/interop matrix).
- Holder sim: `examples/kunji-node-demo/oid4vc-sim.js` (`npm run oid4vc`) — offer→token→credential, then a
  signed+DCQL request (verified, forgery-rejected) → vp_token → direct_post; `--legacy` runs unsigned+PD.
- **Wallet:** `src/services/credentials.js` `receiveViaOffer` (OpenID4VCI redeem → store), `presentViaOid4vp`
  (`buildVpResponse` — DCQL keyed vs PD), and `fetchVerifierKeys` (the verifier's `.well-known`);
  `CredentialsSheet.jsx` accepts an offer (paste/scan); `PresentCredentialSheet.jsx` is the consent sheet
  (default-deny + linkability caveat + a **"Verified verifier"** badge when the request signature checks
  out), opened from `Dashboard.handleQRScan` (which calls `verifyRequestObject` on a signed request) on an
  `openid4vp://` scan or the `?vp=` deep link (`src/App.jsx`). This **closes the S20 "verifier identity
  unverified" caveat** for signed requests; unsigned requests stay host-bound + flagged.
- The kunji-native `POST /issue` and the login-QR `vc_presentations` paths are **unchanged** (interop is additive).
