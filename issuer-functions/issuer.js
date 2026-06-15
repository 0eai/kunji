// The kunji credential ISSUER (issuer.kunji.cc) — crypto + metadata. A separate origin with its own
// rotation-capable signing-key SET (from the KUNJI_ISSUER_SIGNING_KEY secret); SD-JWT VC only. The credential
// TYPES (age, …) live in credentials.js and the verification METHODS in verify/; this file is type-agnostic.
//
// Predicate pre-baking: an age credential carries `age_over_N` booleans, never a DOB — disclosing a threshold
// leaks the answer, not the birthday. See ../docs/issuer.md and ../docs/verified-credentials.md.
import { ed25519 } from '@noble/curves/ed25519.js';
import { mintCredential } from './vc.js';
import { ISSUER_BRAND, credentialConfigs, getType } from './credentials.js';

export const DEFAULT_KID = 'issuer-key-1';
export const MAX_BATCH = 10; // cap batch issuance (resource exhaustion) [S24]
const DAY = 24 * 3600;
const b64u = (b) => Buffer.from(b).toString('base64url');

// Load the issuer signing-key SET from the KUNJI_ISSUER_SIGNING_KEY secret. Accepts either a bare base64
// Ed25519 secret key (single key) OR a JSON array of `[{ kid, sk, active? }]` for key rotation: every entry's
// PUBLIC key is published in the trust anchor (so credentials signed by a retired key still verify until they
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
  brand: ISSUER_BRAND,
  credential_configurations_supported: credentialConfigs(),
});

export const authServerMetadata = (origin) => ({
  issuer: origin,
  token_endpoint: `${origin}/token`,
  'pre-authorized_grant_anonymous_access_supported': true,
});

// The issuer's trust anchor — the Ed25519 public-key SET a wallet/verifier fetches (cross-origin) to verify
// credentials, plus the brand so a relying party can show WHO issued it. Publishes every key in the set so
// rotation never strands an unexpired credential.
export const issuerWellKnown = (origin, keySet) => ({
  issuer: origin,
  name: `${ISSUER_BRAND.name} issuer`,
  brand: ISSUER_BRAND,
  keys: keySet.keys.map((k) => ({ kid: k.kid, kty: 'OKP', crv: 'Ed25519', x: b64u(k.publicKey) })),
});

// Coarsen iat/exp to the UTC-day boundary so timestamps don't fingerprint WHEN a credential was issued and a
// day's batch copies share one iat/exp (a large anonymity set; critical for v2 batch unlinkability). [S23]
const coarseNowMs = () => Math.floor(Date.now() / 1000 / DAY) * DAY * 1000;

// Mint one SD-JWT VC of credential `type`, bound to `holderJwk` with StatusList `idx`, signed by the active
// key. `claims` are the verified, disclosable claims the type/method produced (e.g. age_over_N booleans).
export const mintTypedCredential = ({ keySet, origin, type, holderJwk, idx, claims, typ }) => {
  const t = getType(type);
  if (!t) throw new Error('unknown_type');
  return mintCredential(keySet.active.secretKey, {
    kid: keySet.active.kid,
    iss: origin,
    vct: t.vct,
    claims,
    holderJwk,
    status: { uri: `${origin}/status/${t.vct}`, idx },
    ttlSeconds: t.ttlSeconds,
    now: coarseNowMs(),
    ...(typ ? { typ } : {}),
  });
};
