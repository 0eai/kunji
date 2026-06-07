// Agentic delegation — capability verification (RP side, Node).
// Node port of src/lib/capability.js: same EdDSA-JWT format, so a capability minted by the
// kunji wallet verifies here byte-for-byte (guarded by tests/capability.parity.test.js).
// See docs/agentic-delegation.md.
import { createHash, randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

const b64u = {
  fromBytes: (b) => Buffer.from(b).toString('base64url'),
  toBytes: (s) => new Uint8Array(Buffer.from(String(s), 'base64url')),
  toString: (s) => Buffer.from(String(s), 'base64url').toString('utf8'),
  fromString: (s) => Buffer.from(String(s), 'utf8').toString('base64url'),
};

const enc = (s) => new TextEncoder().encode(s);

export function signJWS(header, claims, secretKey) {
  const input = `${b64u.fromString(JSON.stringify(header))}.${b64u.fromString(JSON.stringify(claims))}`;
  return `${input}.${b64u.fromBytes(ed25519.sign(enc(input), secretKey))}`;
}
function decodeJWS(token) {
  const p = String(token).split('.');
  if (p.length !== 3) throw new Error('malformed_jwt');
  return {
    header: JSON.parse(b64u.toString(p[0])),
    claims: JSON.parse(b64u.toString(p[1])),
    input: `${p[0]}.${p[1]}`,
    sig: b64u.toBytes(p[2]),
  };
}
function verifyJWS(token, pub) {
  try {
    const d = decodeJWS(token);
    return ed25519.verify(d.sig, enc(d.input), pub) ? { header: d.header, claims: d.claims } : null;
  } catch {
    return null;
  }
}

const pubFromOkpJwk = (jwk) => {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('bad_jwk');
  }
  return b64u.toBytes(jwk.x);
};
const subFromPubBytes = (pubBytes) =>
  createHash('sha256').update(Buffer.from(pubBytes).toString('base64'), 'utf8').digest('hex');

/** Agent-side helper (used by agent-sim): build the holder-of-key proof JWT. */
export function buildAgentProof(agentSecretKey, { audience, challenge, capJti, now = Date.now() }) {
  const jti = randomBytes(16).toString('hex');
  return signJWS(
    { alg: 'EdDSA', typ: 'kunji-agentproof+jwt' },
    { aud: audience, challenge, iat: Math.floor(now / 1000), jti, cap: capJti },
    agentSecretKey,
  );
}

// The signed revocation message — MUST match the wallet (src/services/capability.js revokeMessage).
export const revokeMessage = (jti) => `kunji-revoke-v1:${jti}`;

/**
 * Verify a capability + the agent's proof against a session challenge.
 * `isRevoked(jti)` (optional, may be async) enforces a simple operator denylist (existence).
 * `getRevocation(jti)` (optional, may be async) returns the kunji-hosted signed revocation
 * `{ sig }|null`; a revocation counts ONLY if `sig` (over revokeMessage(jti)) verifies against
 * the capability's OWN key — so only the issuing per-app key can revoke (a forged/bogus entry is
 * ignored).
 * @returns {Promise<{ ok:true, sub, scope, jti } | { ok:false, error }>}
 */
export async function verifyCapabilityAssertion({ capability, agentProof, audience, challenge, now = Date.now(), isRevoked, getRevocation }) {
  let cap;
  try {
    cap = decodeJWS(capability);
  } catch {
    return { ok: false, error: 'malformed_capability' };
  }
  if (cap.header?.typ !== 'kunji-cap+jwt' || cap.header?.alg !== 'EdDSA') {
    return { ok: false, error: 'bad_cap_header' };
  }
  let appPubBytes;
  try {
    appPubBytes = pubFromOkpJwk(cap.header.jwk);
  } catch {
    return { ok: false, error: 'bad_cap_key' };
  }
  if (!verifyJWS(capability, appPubBytes)) return { ok: false, error: 'bad_cap_signature' };

  const c = cap.claims;
  const sub = subFromPubBytes(appPubBytes);
  if (c.sub !== sub) return { ok: false, error: 'sub_mismatch' };
  if (c.aud !== audience) return { ok: false, error: 'audience_mismatch' };
  if (!Array.isArray(c.scope) || c.scope.length === 0) return { ok: false, error: 'no_scope' };
  if (typeof c.exp !== 'number' || now > c.exp * 1000) return { ok: false, error: 'capability_expired' };
  if (isRevoked && (await isRevoked(c.jti))) return { ok: false, error: 'capability_revoked' };
  if (getRevocation) {
    const rev = await getRevocation(c.jti);
    // Only honor a revocation signed by the capability's OWN per-app key (issuer-bound).
    if (rev?.sig) {
      try {
        const sigBytes = new Uint8Array(Buffer.from(String(rev.sig), 'base64'));
        if (ed25519.verify(sigBytes, enc(revokeMessage(c.jti)), appPubBytes)) {
          return { ok: false, error: 'capability_revoked' };
        }
      } catch {
        /* malformed revocation → ignore (the short TTL is the backstop) */
      }
    }
  }

  let agentPubBytes;
  try {
    agentPubBytes = pubFromOkpJwk(c.cnf?.jwk);
  } catch {
    return { ok: false, error: 'bad_cnf' };
  }
  const proof = verifyJWS(agentProof, agentPubBytes);
  if (!proof) return { ok: false, error: 'bad_agent_proof' };
  if (proof.header?.typ !== 'kunji-agentproof+jwt') return { ok: false, error: 'bad_proof_header' };
  const p = proof.claims;
  if (p.aud !== audience) return { ok: false, error: 'proof_audience_mismatch' };
  if (p.challenge !== challenge) return { ok: false, error: 'challenge_mismatch' };
  if (p.cap !== c.jti) return { ok: false, error: 'proof_cap_mismatch' };
  if (typeof p.iat !== 'number' || Math.abs(now - p.iat * 1000) > 120_000) {
    return { ok: false, error: 'stale_proof' };
  }

  return { ok: true, sub, scope: c.scope, jti: c.jti };
}
