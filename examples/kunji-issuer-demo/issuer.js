// kunji issuer demo — the ISSUER half of verified credentials.
//
// Signs SD-JWT VCs about a holder, publishes its keys at /.well-known/kunji-issuer.json (the RP's
// trust anchor — HTTPS, not kunji), and keeps a StatusList for revocation. Predicate pre-baking:
// it issues `age_over_18: true`, never a DOB, so disclosing it leaks the answer, not the birthday.
// The issuer's Ed25519 key persists to .issuer-key (git-ignored). See ../../docs/verified-credentials.md.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { mintCredential } from './vc.js';

const KEYFILE = new URL('./.issuer-key', import.meta.url);
const KID = 'issuer-key-1';
const b64u = (b) => Buffer.from(b).toString('base64url');

const loadIssuerKey = () => {
  let sk;
  if (existsSync(KEYFILE)) {
    sk = new Uint8Array(Buffer.from(readFileSync(KEYFILE, 'utf8').trim(), 'base64'));
  } else {
    ({ secretKey: sk } = ed25519.keygen());
    writeFileSync(KEYFILE, Buffer.from(sk).toString('base64'));
  }
  return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) };
};

// The issuer's own public origin — the `iss` baked into credentials and the host the RP fetches
// keys from. Override for a real domain; defaults to the local dev origin.
export const issuerOrigin = () =>
  (process.env.ISSUER_ORIGIN || `http://localhost:${process.env.PORT || 4000}`).replace(/\/$/, '');

export const wellKnown = () => ({
  issuer: issuerOrigin(),
  name: 'kunji issuer demo',
  keys: [{ kid: KID, kty: 'OKP', crv: 'Ed25519', x: b64u(loadIssuerKey().publicKey) }],
});

// In-memory StatusList — a set of revoked indices. The credential carries status:{ uri, idx };
// the RP's checkStatus fetches GET {uri}?idx= and honors `valid:false` as revoked.
const revoked = new Set();
export const statusUri = () => `${issuerOrigin()}/status/1`;
export const isValid = (idx) => !revoked.has(Number(idx));
export const revoke = (idx) => revoked.add(Number(idx));

let nextIdx = 1;
/** Mint a credential bound to `holderJwk` (the holder's per-issuer key). Predicate-baked claims. */
export const issue = ({ holderJwk, vct, claims }) => {
  const idx = nextIdx++;
  const credential = mintCredential(loadIssuerKey().secretKey, {
    kid: KID,
    iss: issuerOrigin(),
    vct: vct || `${issuerOrigin()}/credentials/age`,
    claims: claims || { age_over_18: true, name: 'Ada Lovelace' },
    holderJwk,
    status: { uri: statusUri(), idx },
    ttlSeconds: 365 * 24 * 3600,
  });
  return { credential, idx };
};
