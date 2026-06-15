// The ISSUER half of the kunji-demo live verified-credentials demo — a Firebase-adapted port of
// examples/kunji-issuer-demo/issuer.js. No filesystem / module state: the Ed25519 signing key comes from
// a Secret (passed in) and the StatusList idx is allocated in Firestore (see index.js). SD-JWT VC only.
//
// Predicate pre-baking: issues `age_over_13/16/18/21` booleans, never a DOB — disclosing a threshold leaks
// the answer, not the birthday. DEMO ONLY: it mints to anyone (rate-limited); a real issuer authenticates
// the subject first. See ../../../docs/verified-credentials.md.
import { ed25519 } from '@noble/curves/ed25519.js';
import { mintCredential } from './vc.js';
import { mintBbsCredential, bbsPublicFromSecret } from './vcBbs.js';
import { bytesToB64u, b64uToBytes } from './bbs.js';

export const KID = 'issuer-key-1';
export const BBS_KID = 'issuer-bbs-1'; // the unlinkable (v3, BBS) signing key — verified-credentials.md §7
export const MAX_BATCH = 10; // cap batch issuance (resource exhaustion) [S24]
const DAY = 24 * 3600;
const b64u = (b) => Buffer.from(b).toString('base64url');

/** Load the issuer Ed25519 keypair from a base64 secret-key string (the ISSUER_SIGNING_KEY secret). */
export const issuerKey = (secretKeyB64) => {
  const secretKey = new Uint8Array(Buffer.from(String(secretKeyB64).trim(), 'base64'));
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
};

// The issuer's BBS keypair from a base64url secret (the ISSUER_BBS_KEY secret). bbsPublicFromSecret is
// async (the BBS lib derives the G2 public key), so this is async; memoized per warm instance so the
// .well-known + verify paths don't re-derive on every request (the secret doesn't change).
let _bbsCache = null;
export const issuerBbsKey = async (secretKeyB64) => {
  const trimmed = String(secretKeyB64).trim();
  if (_bbsCache && _bbsCache.b64 === trimmed) return _bbsCache.keys;
  const secretKey = b64uToBytes(trimmed);
  const keys = { secretKey, publicKey: await bbsPublicFromSecret(secretKey) };
  _bbsCache = { b64: trimmed, keys };
  return keys;
};

export const credentialIssuerMetadata = (origin) => ({
  credential_issuer: origin,
  credential_endpoint: `${origin}/credential`,
  authorization_servers: [origin],
  credential_configurations_supported: {
    age: {
      format: 'vc+sd-jwt',
      vct: 'age',
      cryptographic_binding_methods_supported: ['jwk'],
      credential_signing_alg_values_supported: ['EdDSA'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA'] } },
    },
  },
});

export const authServerMetadata = (origin) => ({
  issuer: origin,
  token_endpoint: `${origin}/token`,
  'pre-authorized_grant_anonymous_access_supported': true,
});

/**
 * The issuer's trust anchor — the Ed25519 public key the wallet/verifier fetch to verify credentials.
 * Pass `bbsPublicKey` (BBS G2 public-key bytes) to ALSO advertise the unlinkable (v3) key, so the
 * wallet's `getIssuerBbsKey` can find it when verifying a BBS presentation.
 */
export const issuerWellKnown = (origin, publicKey, bbsPublicKey) => ({
  issuer: origin,
  name: 'kunji demo issuer',
  keys: [
    { kid: KID, kty: 'OKP', crv: 'Ed25519', x: b64u(publicKey) },
    ...(bbsPublicKey ? [{ kid: BBS_KID, alg: 'BBS', crv: 'BLS12-381-G2', pub: bytesToB64u(bbsPublicKey) }] : []),
  ],
});

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
export const ageClaims = (dob = DEFAULT_DOB) =>
  Object.fromEntries(AGE_THRESHOLDS.map((n) => [`age_over_${n}`, ageOf(dob) >= n]));

// Coarsen iat/exp to the UTC-day boundary so timestamps don't fingerprint WHEN a credential was issued
// and a day's batch copies share one iat/exp (a large anonymity set; critical for v2 batch unlinkability). [S23]
const coarseNowMs = () => Math.floor(Date.now() / 1000 / DAY) * DAY * 1000;

/** Mint one age SD-JWT VC bound to `holderJwk` with StatusList `idx`. `typ` opts into the `dc+sd-jwt` name. */
export const mintAgeCredential = ({ secretKey, origin, holderJwk, idx, typ }) =>
  mintCredential(secretKey, {
    kid: KID,
    iss: origin,
    vct: 'age',
    claims: ageClaims(),
    holderJwk,
    status: { uri: `${origin}/status/1`, idx },
    ttlSeconds: 365 * DAY,
    now: coarseNowMs(),
    ...(typ ? { typ } : {}),
  });

/**
 * Mint an UNLINKABLE (BBS, v3) age credential — one credential derives a fresh randomized ZK proof per
 * presentation (no holderJwk, no StatusList idx). Same predicate pre-baking; the header carries a coarse
 * (day) exp. `holderBinding` (the wallet's master-key-derived secret, base64url) is signed as an
 * always-undisclosed message for non-transferability; we sign it but never store it. Returns a BBS blob.
 */
export const issueBbs = async ({ secretKey, publicKey, origin, dob, vct, claims, holderBinding }) =>
  mintBbsCredential(secretKey, publicKey, {
    iss: origin,
    vct: vct || 'age',
    claims: claims || ageClaims(dob),
    holderSecret: holderBinding ? b64uToBytes(holderBinding) : undefined,
    ttlSeconds: 365 * DAY,
  });
