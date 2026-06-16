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

// --- Scope grammar (docs/scope.md) — RP enforcement --------------------------
// A scope item is a string or `{ id, ...constraints }`. `scopeSatisfies(granted, required)` answers
// whether the granted scope covers what's required (exact id, `verb:*` wildcard, and constraint
// ceilings like `max`). Mirrors src/lib/capability.js. `login` is implied by a valid assertion.
const normalizeScopeItem = (item) => (typeof item === 'string' ? { id: item } : { ...item });
const parseAmount = (v) => {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]{0,8})\s*$/.exec(String(v));
  return m ? { n: parseFloat(m[1]), ccy: m[2].toUpperCase() } : null;
};
const idMatches = (grantedId, requiredId) => {
  if (grantedId === requiredId) return true;
  if (grantedId.endsWith(':*')) {
    const prefix = grantedId.slice(0, -1);
    return requiredId.startsWith(prefix) && requiredId.length > prefix.length;
  }
  return false;
};
const constraintsSatisfied = (granted, required) => {
  for (const [k, rv] of Object.entries(required)) {
    if (k === 'id' || !(k in granted)) continue;
    const gv = granted[k];
    if (k === 'max') {
      const ga = parseAmount(gv);
      const ra = parseAmount(rv);
      if (ga && ra) {
        if (ga.ccy !== ra.ccy || ra.n > ga.n) return false;
        continue;
      }
    }
    if (gv !== rv) return false;
  }
  return true;
};
export const scopeSatisfies = (granted, required) => {
  if (!Array.isArray(granted) || !Array.isArray(required)) return false;
  const g = granted.map(normalizeScopeItem);
  return required.map(normalizeScopeItem).every((req) => {
    if (req.id === 'login') return true;
    return g.some((gr) => idMatches(gr.id, req.id) && constraintsSatisfied(gr, req));
  });
};

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
export async function verifyCapabilityAssertion({ capability, agentProof, audience, challenge, now = Date.now(), isRevoked, getRevocation, chain }) {
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

  // Optional delegation chain (root → leaf): each link narrows scope, is signed by the previous
  // link's cnf key, and cannot outlive its parent. An empty chain behaves exactly as before.
  let cnfJwk = c.cnf?.jwk;
  let effScope = c.scope;
  let effJti = c.jti;
  let prevJti = c.jti;
  let prevScope = c.scope;
  let prevExp = c.exp;
  const chainArr = Array.isArray(chain) ? chain : [];
  if (chainArr.length > 4) return { ok: false, error: 'chain_too_deep' };
  for (const linkToken of chainArr) {
    let prevPub;
    try {
      prevPub = pubFromOkpJwk(cnfJwk);
    } catch {
      return { ok: false, error: 'bad_cnf' };
    }
    const link = verifyJWS(linkToken, prevPub);
    if (!link) return { ok: false, error: 'bad_delegation_signature' };
    if (link.header?.typ !== 'kunji-capdel+jwt') return { ok: false, error: 'bad_delegation_header' };
    const lc = link.claims;
    if (lc.aud !== audience) return { ok: false, error: 'delegation_audience_mismatch' };
    if (lc.parent !== prevJti) return { ok: false, error: 'delegation_parent_mismatch' };
    if (!Array.isArray(lc.scope) || lc.scope.length === 0) return { ok: false, error: 'no_scope' };
    if (!scopeSatisfies(prevScope, lc.scope)) return { ok: false, error: 'delegation_not_subset' };
    if (typeof lc.exp !== 'number' || lc.exp > prevExp || now > lc.exp * 1000) {
      return { ok: false, error: 'delegation_expired' };
    }
    cnfJwk = lc.cnf?.jwk;
    prevJti = lc.jti;
    prevScope = lc.scope;
    prevExp = lc.exp;
    effScope = lc.scope;
    effJti = lc.jti;
  }

  // Holder-of-key: the LEAF agent proves possession of its cnf key against THIS challenge.
  let agentPubBytes;
  try {
    agentPubBytes = pubFromOkpJwk(cnfJwk);
  } catch {
    return { ok: false, error: 'bad_cnf' };
  }
  const proof = verifyJWS(agentProof, agentPubBytes);
  if (!proof) return { ok: false, error: 'bad_agent_proof' };
  if (proof.header?.typ !== 'kunji-agentproof+jwt') return { ok: false, error: 'bad_proof_header' };
  const p = proof.claims;
  if (p.aud !== audience) return { ok: false, error: 'proof_audience_mismatch' };
  if (p.challenge !== challenge) return { ok: false, error: 'challenge_mismatch' };
  if (p.cap !== effJti) return { ok: false, error: 'proof_cap_mismatch' };
  if (typeof p.iat !== 'number' || Math.abs(now - p.iat * 1000) > 120_000) {
    return { ok: false, error: 'stale_proof' };
  }

  return { ok: true, sub, scope: effScope, jti: effJti };
}
