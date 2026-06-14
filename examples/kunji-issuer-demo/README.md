# kunji issuer demo — verified credentials

A framework-free, Firebase-free **credential issuer**. It signs **SD-JWT VC**s about a holder,
publishes its signing keys at `/.well-known/kunji-issuer.json`, and serves a **StatusList** for
revocation. A relying party verifies a presented credential **locally** against these keys —
**kunji is never in the path** (the §6 trust model, with the issuer as the signer). See
[`../../docs/verified-credentials.md`](../../docs/verified-credentials.md).

```bash
npm install
PORT=4000 npm start        # → http://localhost:4000
```

## Endpoints

| Method | Path | Body / Query | Returns |
|---|---|---|---|
| GET | `/.well-known/kunji-issuer.json` | — | `{ issuer, name, keys:[{kid,kty,crv,x}] }` |
| POST | `/issue` | `{ holderJwk, vct?, claims? }` | `{ credential, idx, issuer }` |
| GET | `/status/1` | `?idx=N` | `{ valid }` |
| POST | `/status/revoke` | `{ idx }` | `{ ok, revoked }` (demo control) |
| GET | `/.well-known/openid-credential-issuer` | — | OpenID4VCI issuer metadata |
| GET | `/.well-known/oauth-authorization-server` | — | token endpoint metadata |
| GET | `/credential-offer` | — | `{ offer, offerUri }` (pre-authorized_code) |
| POST | `/token` | `{ grant_type, pre-authorized_code }` | `{ access_token, c_nonce, … }` |
| POST | `/credential` | `Bearer` + `{ proof:{ proof_type:'jwt', jwt } }` | `{ credential }` |

The last five are the **OpenID4VCI** envelope around the same SD-JWT VC (`/issue` stays the
kunji-native shortcut). The proof JWT's `jwk` becomes the credential's `cnf.jwk`, so holder-of-key is
identical. See [`../../docs/oid4vc.md`](../../docs/oid4vc.md). The matching OpenID4VP presentation +
the end-to-end sim live in [`../kunji-node-demo`](../kunji-node-demo) (`npm run oid4vc`).

- **Predicate pre-baking:** by default it issues `age_over_18: true` (never a DOB), so disclosing
  the predicate leaks the answer, not the birthday.
- **Holder binding:** the credential's `cnf` is the holder key the request carries (`holderJwk`); the
  holder proves possession at presentation with a Key-Binding JWT — a stolen credential is useless.
- The issuer's Ed25519 key persists to `.issuer-key` (git-ignored).

## Full headless flow (no wallet, no deploy)

Run this issuer **and** the RP demo, then let the RP's wallet-sim act as the holder:

```bash
# terminal 1 — the issuer
cd examples/kunji-issuer-demo && npm install && PORT=4000 npm start

# terminal 2 — the relying party + holder sim
cd examples/kunji-node-demo && npm install
ISSUER=http://localhost:4000 npm run wallet -- --vc            # → login carries a VERIFIED age_over_18
ISSUER=http://localhost:4000 npm run wallet -- --vc --revoke   # → presentation REJECTED (revoked)
```
