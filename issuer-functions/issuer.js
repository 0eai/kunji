// The kunji age-credential ISSUER (issuer.kunji.cc). Adapted from the kunji-demo issuer port, but this is
// the REAL issuer: a separate origin, its own signing-key SET (rotation-capable), and — once Phase 2 lands —
// minting only AFTER an IDV proofing gate. No filesystem / module state: the Ed25519 signing key(s) come
// from a Secret and the StatusList idx is allocated in Firestore (see index.js). SD-JWT VC only.
//
// Predicate pre-baking: issues `age_over_13/16/18/21` booleans, never a DOB — disclosing a threshold leaks
// the answer, not the birthday. The booleans are derived from a vendor-verified age (Phase 2); never the DOB.
// See ../docs/verified-credentials.md and the plan in ../docs/issuer.md.
import { ed25519 } from '@noble/curves/ed25519.js';
import { mintCredential } from './vc.js';

export const DEFAULT_KID = 'issuer-key-1';
export const MAX_BATCH = 10; // cap batch issuance (resource exhaustion) [S24]
const DAY = 24 * 3600;
const b64u = (b) => Buffer.from(b).toString('base64url');

// Load the issuer signing-key SET from the ISSUER_SIGNING_KEY secret. Accepts either a bare base64 Ed25519
// secret key (single key) OR a JSON array of `[{ kid, sk, active? }]` for key rotation: every entry's PUBLIC
// key is published in the trust anchor (so credentials signed by a retired key still verify until they
// expire), but signing always uses the ACTIVE key (the first `active:true`, else the first entry).
export const loadKeySet = (secretValue) => {
  const raw = String(secretValue).trim();
  let entries;
  try {
    const parsed = JSON.parse(raw);
    entries = Array.isArray(parsed) ? parsed : [parsed];
    if (!entries.length || typeof entries[0] !== 'object') throw new Error('not_keyset');
  } catch {
    entries = [{ kid: DEFAULT_KID, sk: raw }];
  }
  const keys = entries.map((e, i) => {
    const secretKey = new Uint8Array(Buffer.from(String(e.sk).trim(), 'base64'));
    return {
      kid: e.kid || `issuer-key-${i + 1}`,
      active: e.active === true,
      secretKey,
      publicKey: ed25519.getPublicKey(secretKey),
    };
  });
  const active = keys.find((k) => k.active) || keys[0];
  return { keys, active };
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

// The issuer's trust anchor — the Ed25519 public-key SET the wallet/verifier fetch (cross-origin) to verify
// credentials. Publishes every key in the set so rotation never strands an unexpired credential.
export const issuerWellKnown = (origin, keySet) => ({
  issuer: origin,
  name: 'kunji age issuer',
  keys: keySet.keys.map((k) => ({ kid: k.kid, kty: 'OKP', crv: 'Ed25519', x: b64u(k.publicKey) })),
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
// Derive the boolean thresholds from a verified age (the IDV result, Phase 2). `dob` is the DEMO/test path
// only (open-mint); production passes a verified integer age via `ageClaimsFromAge`.
export const ageClaims = (dob = DEFAULT_DOB) =>
  Object.fromEntries(AGE_THRESHOLDS.map((n) => [`age_over_${n}`, ageOf(dob) >= n]));
export const ageClaimsFromAge = (age) =>
  Object.fromEntries(AGE_THRESHOLDS.map((n) => [`age_over_${n}`, Number(age) >= n]));

// Coarsen iat/exp to the UTC-day boundary so timestamps don't fingerprint WHEN a credential was issued
// and a day's batch copies share one iat/exp (a large anonymity set; critical for v2 batch unlinkability). [S23]
const coarseNowMs = () => Math.floor(Date.now() / 1000 / DAY) * DAY * 1000;

// Mint one age SD-JWT VC bound to `holderJwk` with StatusList `idx`, signed by the active key in `keySet`.
// `claims` (pre-baked booleans) is preferred; falls back to the demo default. `typ` opts into `dc+sd-jwt`.
export const mintAgeCredential = ({ keySet, origin, holderJwk, idx, claims, typ }) =>
  mintCredential(keySet.active.secretKey, {
    kid: keySet.active.kid,
    iss: origin,
    vct: 'age',
    claims: claims || ageClaims(),
    holderJwk,
    status: { uri: `${origin}/status/1`, idx },
    ttlSeconds: 365 * DAY,
    now: coarseNowMs(),
    ...(typ ? { typ } : {}),
  });
