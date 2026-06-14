// kunji issuer demo — the ISSUER half of verified credentials.
//
// Signs SD-JWT VCs about a holder, publishes its keys at /.well-known/kunji-issuer.json (the RP's
// trust anchor — HTTPS, not kunji), and keeps a StatusList for revocation. Predicate pre-baking:
// it issues `age_over_18: true`, never a DOB, so disclosing it leaks the answer, not the birthday.
// The issuer's Ed25519 key persists to .issuer-key (git-ignored). See ../../docs/verified-credentials.md.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { mintCredential } from './vc.js';
import { mintBbsCredential, bbsKeyGen, bbsPublicFromSecret } from './vcBbs.js';
import { bytesToB64u, b64uToBytes } from './bbs.js';

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

// The issuer's BBS key (verified-credentials.md §7 v3 — unlinkable credentials). Persisted to
// .issuer-bbs-key (git-ignored). Loaded once at startup (top-level await) so wellKnown() is sync.
const BBS_KEYFILE = new URL('./.issuer-bbs-key', import.meta.url);
const BBS_KID = 'issuer-bbs-1';
const loadIssuerBbsKey = async () => {
  let secretKey;
  if (existsSync(BBS_KEYFILE)) {
    secretKey = b64uToBytes(readFileSync(BBS_KEYFILE, 'utf8').trim());
  } else {
    ({ secretKey } = await bbsKeyGen());
    writeFileSync(BBS_KEYFILE, bytesToB64u(secretKey));
  }
  return { secretKey, publicKey: await bbsPublicFromSecret(secretKey) };
};
const issuerBbs = await loadIssuerBbsKey();

// The issuer's own public origin — the `iss` baked into credentials and the host the RP fetches
// keys from. Override for a real domain; defaults to the local dev origin.
export const issuerOrigin = () =>
  (process.env.ISSUER_ORIGIN || `http://localhost:${process.env.PORT || 4000}`).replace(/\/$/, '');

export const wellKnown = () => ({
  issuer: issuerOrigin(),
  name: 'kunji issuer demo',
  keys: [
    { kid: KID, kty: 'OKP', crv: 'Ed25519', x: b64u(loadIssuerKey().publicKey) },
    // The BBS public key the wallet/verifier uses to verify unlinkable (v3) presentations.
    { kid: BBS_KID, alg: 'BBS', crv: 'BLS12-381-G2', pub: bytesToB64u(issuerBbs.publicKey) },
  ],
});

// In-memory StatusList — a set of revoked indices. The credential carries status:{ uri, idx };
// the RP's checkStatus fetches GET {uri}?idx= and honors `valid:false` as revoked.
const revoked = new Set();
export const statusUri = () => `${issuerOrigin()}/status/1`;
export const isValid = (idx) => !revoked.has(Number(idx));
export const revoke = (idx) => revoked.add(Number(idx));

// Pre-baked age thresholds. The DOB is used only to COMPUTE these booleans, then discarded — only the
// booleans are signed into the credential, so a holder can prove "16+" without revealing the birthday.
const AGE_THRESHOLDS = [13, 16, 18, 21];
const DEFAULT_DOB = '1990-01-01';
const ageOf = (dob) => {
  const b = new Date(dob);
  const now = new Date();
  let age = now.getUTCFullYear() - b.getUTCFullYear();
  const m = now.getUTCMonth() - b.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < b.getUTCDate())) age--;
  return age;
};
const ageClaims = (dob) => {
  const age = ageOf(dob);
  return Object.fromEntries(AGE_THRESHOLDS.map((n) => [`age_over_${n}`, age >= n]));
};

const DAY = 24 * 3600;

// Coarsen issuance to the UTC-day boundary so iat/exp don't fingerprint WHEN a credential was issued,
// and so every credential the issuer mints in a day shares one iat/exp (a large anonymity set). Critical
// for batch unlinkability: otherwise a holder's one-time copies all carry the SAME per-second timestamp,
// which a colluding verifier can use to relink them. Issuers SHOULD coarsen. [S23]
const coarseNowMs = () => Math.floor(Date.now() / 1000 / DAY) * DAY * 1000;

// Cap batch issuance so a caller can't demand an unbounded number of copies (resource exhaustion). [S24]
export const MAX_BATCH = 10;

let nextIdx = 1;
/**
 * Mint an age credential bound to `holderJwk`. Bakes `age_over_13/16/18/21` from `dob` (defaults to
 * an adult) — booleans ONLY; the DOB is never put in the credential. `claims`/`vct` override (tests).
 */
export const issue = ({ holderJwk, dob, vct, claims }) => {
  const idx = nextIdx++;
  const credential = mintCredential(loadIssuerKey().secretKey, {
    kid: KID,
    iss: issuerOrigin(),
    vct: vct || 'age',
    claims: claims || ageClaims(dob || DEFAULT_DOB),
    holderJwk,
    status: { uri: statusUri(), idx },
    ttlSeconds: 365 * DAY,
    now: coarseNowMs(), // day-coarse iat/exp — no per-second handle across a batch [S23]
  });
  return { credential, idx };
};

/**
 * Batch issuance for unlinkability v2 (verified-credentials.md §7): one one-time-use credential per
 * holder key, each with its own random salts (⇒ distinct issuer signature) and its own StatusList idx
 * (⇒ per-copy revocation, and the idx doesn't link the copies). The wallet spends one copy per
 * presentation, so no two presentations share a correlation handle. Returns `[{ credential, idx }, …]`.
 */
export const issueBatch = ({ holderJwks, dob, vct, claims }) =>
  (holderJwks || []).map((holderJwk) => issue({ holderJwk, dob, vct, claims }));

/**
 * Mint an UNLINKABLE (BBS, v3) age credential. No holderJwk: a BBS credential needs no per-issuance
 * holder key — ONE credential derives a fresh randomized proof per presentation. Same predicate
 * pre-baking; the header carries a coarse (day) exp. Returns `{ credential }` (a BBS credential blob).
 */
export const issueBbs = async ({ dob, vct, claims }) => ({
  credential: await mintBbsCredential(issuerBbs.secretKey, issuerBbs.publicKey, {
    iss: issuerOrigin(),
    vct: vct || 'age',
    claims: claims || ageClaims(dob || DEFAULT_DOB),
    ttlSeconds: 365 * DAY,
  }),
});
