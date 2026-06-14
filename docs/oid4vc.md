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
| `vc:<vct>[@iss]#claim,…` scope ([`scope.md`](./scope.md)) | a `presentation_definition` input_descriptor (`$.vct` const + claim `path`s) — `pdToVcQuery` is the inverse |
| StatusList `status:{uri,idx}` + `checkStatus` | unchanged — the verifier polls the issuer's status endpoint |
| `verifyCredentialPresentation` | `verifyVpToken` wraps it, then enforces the PD constraints (vct + each requested claim `=== true`) |

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

## 4. OpenID4VP (presentation) — direct_post + presentation_definition

```
verifier ──GET /oid4vp/request──▶ openid4vp://?response_type=vp_token&client_id=…&response_mode=direct_post&response_uri=…&nonce=…&presentation_definition=<JSON>&state=…
holder   builds vp_token = buildPresentation(sdjwt, disclose, aud=client_id, nonce) ; presentation_submission
holder   ──POST {response_uri}  { vp_token, presentation_submission, state }──▶ verified locally → { approved, claims }
```

Lib: `parseAuthorizationRequest`, `pdToVcQuery`, `buildVpToken`, `buildPresentationSubmission`,
`verifyVpToken`. The verifier resolves issuer keys from the credential's own `.well-known` — **no kunji
server in the path** — and checks the KB-JWT `aud`/`nonce` against the request, exactly like the login path.

## 5. Scope & pinned shapes

Implemented: the **pre-authorized_code** grant (VCI), **direct_post** + **presentation_definition** (VP),
SD-JWT VC only, EdDSA. Deferred (documented, not built): the `authorization_code` grant + PKCE, DPoP,
signed/encrypted request objects and `request_uri`/`client_id` scheme prefixes, DCQL (the
presentation_definition successor), and the in-flight `vc+sd-jwt` → `dc+sd-jwt` format rename (kept as the
`SD_JWT_VC_FORMAT` knob in `oid4vc.js`). These are envelope-only extensions — none touches the SD-JWT VC core.

## 6. Where it lives

- `src/lib/oid4vc.js` — the canonical envelope (wraps `vc.js` + the `capability.js` JWS primitives);
  byte-identical Node port in `examples/kunji-node-demo/oid4vc.js` + `examples/kunji-issuer-demo/oid4vc.js`
  (parity-guarded by `tests/oid4vc.parity.test.js`, like `vc.js`).
- Issuer: `examples/kunji-issuer-demo/oid4vci.js` (offer/token/credential store) + the routes in its `server.js`.
- Verifier: the `/oid4vp/{request,response,result}` routes in `examples/kunji-node-demo/server.js`.
- Holder sim: `examples/kunji-node-demo/oid4vc-sim.js` (`npm run oid4vc`) — offer→token→credential, then
  request→vp_token→direct_post, end-to-end.
- **Wallet:** `src/services/credentials.js` `receiveViaOffer` (OpenID4VCI redeem → store) and
  `presentViaOid4vp` (vp_token + direct_post); `CredentialsSheet.jsx` accepts an offer (paste/scan);
  `PresentCredentialSheet.jsx` is the consent sheet (default-deny + linkability caveat), opened from
  `Dashboard.handleQRScan` on an `openid4vp://` scan or the `?vp=` deep link (`src/App.jsx`).
- The kunji-native `POST /issue` and the login-QR `vc_presentations` paths are **unchanged** (interop is additive).
