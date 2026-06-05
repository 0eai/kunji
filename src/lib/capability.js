/**
 * Agentic delegation — capability tokens (EdDSA compact JWT).
 *
 * A capability lets a user authorize an agent to act for them at ONE app, WITHOUT giving
 * the agent any kunji key. It is a JWT signed by the user's per-app key
 * (`deriveAppKeyPair(masterKey, audience)` — the same key that yields `sub`), bound to the
 * AGENT's own keypair (holder-of-key, RFC 7800 `cnf`), scoped, time-boxed, and revocable.
 *
 * To use it the agent signs a fresh RP challenge with its own key (the agent-proof JWT), so
 * a stolen capability is useless. The RP verifies both locally (no kunji backend), exactly
 * like the §6 assertion. Pure + dependency-light (only @noble ed25519 + the base64 helpers);
 * the same verifier runs in the wallet, the tests, and the RP, guaranteeing parity.
 *
 * See docs/agentic-delegation.md.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveAppKeyPair, exportEd25519PublicKey } from './crypto/ed25519';
import { bufferToBase64, base64ToBuffer } from './crypto/helpers';

// --- base64url ---------------------------------------------------------------
const b64uFromBytes = (bytes) =>
  bufferToBase64(bytes.buffer ?? bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const b64uFromString = (str) => b64uFromBytes(new TextEncoder().encode(str));
const b64uToBytes = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
  return new Uint8Array(base64ToBuffer(t + pad));
};
const b64uToString = (s) => new TextDecoder().decode(b64uToBytes(s));

// --- EdDSA compact JWS --------------------------------------------------------
const signJWS = (header, claims, secretKey) => {
  const input = `${b64uFromString(JSON.stringify(header))}.${b64uFromString(JSON.stringify(claims))}`;
  const sig = ed25519.sign(new TextEncoder().encode(input), secretKey);
  return `${input}.${b64uFromBytes(sig)}`;
};
const decodeJWS = (token) => {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('malformed_jwt');
  return {
    header: JSON.parse(b64uToString(parts[0])),
    claims: JSON.parse(b64uToString(parts[1])),
    input: `${parts[0]}.${parts[1]}`,
    sig: b64uToBytes(parts[2]),
  };
};
const verifyJWS = (token, pubBytes) => {
  try {
    const d = decodeJWS(token);
    return ed25519.verify(d.sig, new TextEncoder().encode(d.input), pubBytes)
      ? { header: d.header, claims: d.claims }
      : null;
  } catch {
    return null;
  }
};

// --- OKP (Ed25519) JWK --------------------------------------------------------
const okpJwk = (pubBytes) => ({ kty: 'OKP', crv: 'Ed25519', x: b64uFromBytes(pubBytes) });
const pubFromOkpJwk = (jwk) => {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('bad_jwk');
  }
  return b64uToBytes(jwk.x);
};

// `sub = hex(SHA-256(utf8(publicKeyBase64)))` — identical to identity.deriveSubFromPublicKey.
const subFromPubB64 = async (pubB64) => {
  const digest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubB64));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

const randomJti = () => {
  const b = new Uint8Array(16);
  window.crypto.getRandomValues(b);
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * Mint a capability for `agentPubB64` to act at `audience` within `scope` for `ttlSeconds`.
 * Signed by the per-app key for that audience. Returns the JWT + metadata.
 */
export const mintCapability = async (
  masterKey,
  { audience, scope, ttlSeconds, agentPubB64, now = Date.now() },
) => {
  if (!audience) throw new Error('audience_required');
  if (!Array.isArray(scope) || scope.length === 0) throw new Error('scope_required');
  if (!agentPubB64) throw new Error('agent_key_required');

  const { secretKey, publicKey } = await deriveAppKeyPair(masterKey, audience);
  const appPubB64 = exportEd25519PublicKey(publicKey);
  const sub = await subFromPubB64(appPubB64);
  const agentPubBytes = new Uint8Array(base64ToBuffer(agentPubB64));

  const iat = Math.floor(now / 1000);
  const exp = iat + Math.max(1, Math.floor(ttlSeconds || 0));
  const jti = randomJti();

  const header = { alg: 'EdDSA', typ: 'kunji-cap+jwt', jwk: okpJwk(publicKey) };
  const claims = { iss: sub, sub, aud: audience, scope, iat, exp, jti, cnf: { jwk: okpJwk(agentPubBytes) } };

  return { capability: signJWS(header, claims, secretKey), appPub: appPubB64, sub, jti, exp };
};

/** Agent-side: sign a fresh RP challenge with the agent key (holder-of-key proof). */
export const buildAgentProof = (agentSecretKey, { audience, challenge, capJti, now = Date.now() }) => {
  const header = { alg: 'EdDSA', typ: 'kunji-agentproof+jwt' };
  const claims = { aud: audience, challenge, iat: Math.floor(now / 1000), jti: randomJti(), cap: capJti };
  return signJWS(header, claims, agentSecretKey);
};

/**
 * RP-side: verify a capability + the agent's proof against a session challenge.
 * `isRevoked(jti)` (optional, may be async) lets the RP enforce a revocation denylist.
 * @returns {{ ok:true, sub, scope, jti } | { ok:false, error }}
 */
export const verifyCapabilityAssertion = async ({
  capability,
  agentProof,
  audience,
  challenge,
  now = Date.now(),
  isRevoked,
}) => {
  // 1. capability structure + self-verifying signature (key is in the header)
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
  // 2. the capability really is this user's per-app identity
  const sub = await subFromPubB64(bufferToBase64(appPubBytes.buffer ?? appPubBytes));
  if (c.sub !== sub) return { ok: false, error: 'sub_mismatch' };
  // 3. audience / scope / expiry / revocation
  if (c.aud !== audience) return { ok: false, error: 'audience_mismatch' };
  if (!Array.isArray(c.scope) || c.scope.length === 0) return { ok: false, error: 'no_scope' };
  if (typeof c.exp !== 'number' || now > c.exp * 1000) return { ok: false, error: 'capability_expired' };
  if (isRevoked && (await isRevoked(c.jti))) return { ok: false, error: 'capability_revoked' };

  // 4. holder-of-key: the agent proves possession of the cnf key against THIS challenge
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
};
