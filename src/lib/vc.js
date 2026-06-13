/**
 * Verified credentials — SD-JWT VC (holder + verifier).
 *
 * A trusted ISSUER signs a credential about the user (an SD-JWT: issuer JWS + salted, hashed
 * disclosures); the user HOLDS it bound to a per-issuer holder key (`cnf`, via
 * `deriveCredentialHolderKey`); and presents it to an RP with **selective disclosure** + a
 * **Key-Binding JWT** proving holder-of-key against the RP's challenge. The RP verifies LOCALLY —
 * issuer signature (keys discovered out-of-band), disclosure hashes, holder binding, expiry,
 * StatusList — with **no kunji backend in the path** (the §6 trust model, a different signer).
 *
 * Reuses the EdDSA JWS primitives from capability.js; `mintCredential` here is the canonical issuer
 * format (the kunji-issuer-demo mirrors it in Node; the wallet itself never mints).
 * See docs/verified-credentials.md.
 */
import { deriveCredentialHolderKey } from './crypto/ed25519';
import { bufferToBase64, base64ToBuffer } from './crypto/helpers';
import { signJWS, decodeJWS, verifyJWS, okpJwk, pubFromOkpJwk, scopeId } from './capability';

export { deriveCredentialHolderKey };

// --- base64url + sha256 (disclosures) ----------------------------------------
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
const sha256 = async (bytes) => new Uint8Array(await window.crypto.subtle.digest('SHA-256', bytes));

/** base64url(SHA-256(ascii(disclosureString))) — the value placed in the SD-JWT `_sd` array. */
export const disclosureHash = async (disclosureStr) =>
  b64uFromBytes(await sha256(new TextEncoder().encode(disclosureStr)));

const randomSalt = () => {
  const b = new Uint8Array(16);
  window.crypto.getRandomValues(b);
  return b64uFromBytes(b);
};

// --- Issuer: mint an SD-JWT VC (canonical format; the demo issuer mirrors this) --------------
export const mintCredential = async (
  issuerSecretKey,
  { kid, iss, vct, claims, holderJwk, status, ttlSeconds, now = Date.now() },
) => {
  const iat = Math.floor(now / 1000);
  const exp = iat + Math.max(1, Math.floor(ttlSeconds || 0));
  const disclosures = [];
  const _sd = [];
  for (const [name, value] of Object.entries(claims || {})) {
    const disc = b64uFromString(JSON.stringify([randomSalt(), name, value]));
    disclosures.push(disc);
    _sd.push(await disclosureHash(disc));
  }
  const header = { alg: 'EdDSA', typ: 'vc+sd-jwt', kid };
  const payload = { iss, vct, iat, exp, cnf: { jwk: holderJwk }, _sd_alg: 'sha-256', _sd };
  if (status) payload.status = status;
  const issuerJws = signJWS(header, payload, issuerSecretKey);
  return [issuerJws, ...disclosures, ''].join('~'); // trailing ~ (no Key-Binding yet)
};

// --- Holder: parse, select, present ------------------------------------------
export const parseSdJwt = (sdjwt) => {
  const parts = String(sdjwt).split('~');
  const issuerJws = parts[0];
  const { header: issuerHeader, claims: issuerClaims } = decodeJWS(issuerJws);
  const disclosures = parts
    .slice(1)
    .filter((p) => p.length > 0)
    .map((raw) => {
      const [salt, name, value] = JSON.parse(b64uToString(raw));
      return { raw, salt, name, value };
    });
  return { issuerJws, issuerHeader, issuerClaims, disclosures };
};

/** Build the holder JWK to hand an issuer at request time (binds the credential to the holder key). */
export const holderJwkFor = (holderPublicKey) => okpJwk(holderPublicKey);

const buildKeyBindingJwt = ({ holderSecretKey, audience, nonce, sdHash, now = Date.now() }) =>
  signJWS(
    { typ: 'kb+jwt', alg: 'EdDSA' },
    { aud: audience, nonce, iat: Math.floor(now / 1000), sd_hash: sdHash },
    holderSecretKey,
  );

/**
 * Present a held SD-JWT to an RP: reveal only `disclose` (claim names), and bind it to THIS
 * (audience, nonce) with a Key-Binding JWT signed by the holder key. Returns the presentation
 * string `issuerJws~sel1~…~<KB-JWT>`.
 */
export const buildPresentation = async ({
  sdjwt,
  disclose,
  audience,
  nonce,
  holderSecretKey,
  now = Date.now(),
}) => {
  const parsed = parseSdJwt(sdjwt);
  const want = new Set(disclose || []);
  const selected = parsed.disclosures.filter((d) => want.has(d.name)).map((d) => d.raw);
  const sdPart = [parsed.issuerJws, ...selected, ''].join('~'); // SD-JWT incl. trailing ~ before KB
  const sdHash = await disclosureHash(sdPart);
  return sdPart + buildKeyBindingJwt({ holderSecretKey, audience, nonce, sdHash, now });
};

/**
 * Parse a `vc:<vct>[@issuer][#claim,…]` scope id → `{ vct, iss?, disclose: string[] }`, or `null` if
 * it isn't a `vc:` id. `#claim,…` selects which credential claims (e.g. an age predicate) to reveal;
 * `@issuer` pins the issuer. e.g. `vc:age#age_over_16`, `vc:age@https://issuer#age_over_16`.
 */
export const parseVcScope = (id) => {
  if (typeof id !== 'string' || !id.startsWith('vc:')) return null;
  let rest = id.slice(3);
  let disclose = [];
  const hash = rest.indexOf('#');
  if (hash >= 0) {
    disclose = rest.slice(hash + 1).split(',').filter(Boolean);
    rest = rest.slice(0, hash);
  }
  const at = rest.indexOf('@');
  const vct = at >= 0 ? rest.slice(0, at) : rest;
  const iss = at >= 0 ? rest.slice(at + 1) : undefined;
  return { vct, iss, disclose };
};

/**
 * Which held credentials satisfy the `vc:` requests in `scope`, and which claims each should
 * disclose. `held`: [{ vct, iss, sdjwt }]. Returns `[{ cred, disclose }]`.
 */
export const matchCredentialsByScope = (held, scope) => {
  const reqs = (scope || []).map(scopeId).map(parseVcScope).filter(Boolean);
  const out = [];
  for (const cred of held || []) {
    for (const r of reqs) {
      if (cred.vct === r.vct && (!r.iss || cred.iss === r.iss)) out.push({ cred, disclose: r.disclose });
    }
  }
  return out;
};

// --- Verifier (RP-side; also the reference the demo's Node port mirrors) ----------------------
/**
 * Verify a credential presentation, locally. `getIssuerKeys(iss)` resolves the issuer's OKP keys
 * (from its `.well-known` — injectable, so tests run offline); `checkStatus(uri, idx)` returns
 * `false` if the credential is revoked (also injectable). Both mirror capability's `getRevocation`.
 * @returns {Promise<{ ok:true, iss, vct, claims } | { ok:false, error }>}
 */
export const verifyCredentialPresentation = async ({
  presentation,
  getIssuerKeys,
  checkStatus,
  audience,
  nonce,
  now = Date.now(),
}) => {
  const parts = String(presentation).split('~');
  if (parts.length < 2) return { ok: false, error: 'malformed_presentation' };
  const issuerJws = parts[0];
  const kbJwt = parts[parts.length - 1];
  const discRaw = parts.slice(1, -1).filter((p) => p.length > 0);

  // 1. issuer signature (key discovered by iss + kid)
  let issuer;
  try {
    issuer = decodeJWS(issuerJws);
  } catch {
    return { ok: false, error: 'malformed_credential' };
  }
  if (issuer.header?.typ !== 'vc+sd-jwt' || issuer.header?.alg !== 'EdDSA') {
    return { ok: false, error: 'bad_credential_header' };
  }
  const c = issuer.claims;
  if (!c?.iss) return { ok: false, error: 'no_issuer' };
  let keys;
  try {
    keys = await getIssuerKeys(c.iss);
  } catch {
    return { ok: false, error: 'issuer_unresolved' };
  }
  const jwk = (keys || []).find((k) => k.kid === issuer.header.kid) || (keys || [])[0];
  let issuerPub;
  try {
    issuerPub = pubFromOkpJwk(jwk);
  } catch {
    return { ok: false, error: 'bad_issuer_key' };
  }
  if (!verifyJWS(issuerJws, issuerPub)) return { ok: false, error: 'bad_issuer_signature' };

  // 2. expiry
  if (typeof c.exp !== 'number' || now > c.exp * 1000) return { ok: false, error: 'credential_expired' };

  // 3. disclosures must each hash into `_sd`
  const sdSet = new Set(Array.isArray(c._sd) ? c._sd : []);
  const claims = {};
  for (const raw of discRaw) {
    if (!sdSet.has(await disclosureHash(raw))) return { ok: false, error: 'disclosure_not_in_sd' };
    let parsed;
    try {
      parsed = JSON.parse(b64uToString(raw));
    } catch {
      return { ok: false, error: 'bad_disclosure' };
    }
    claims[parsed[1]] = parsed[2];
  }

  // 4. holder binding — the KB-JWT is signed by the cnf key over THIS (audience, nonce) + sd_hash
  let holderPub;
  try {
    holderPub = pubFromOkpJwk(c.cnf?.jwk);
  } catch {
    return { ok: false, error: 'bad_cnf' };
  }
  const kb = verifyJWS(kbJwt, holderPub);
  if (!kb) return { ok: false, error: 'bad_key_binding' };
  if (kb.header?.typ !== 'kb+jwt') return { ok: false, error: 'bad_kb_header' };
  const p = kb.claims;
  if (p.aud !== audience) return { ok: false, error: 'kb_audience_mismatch' };
  if (p.nonce !== nonce) return { ok: false, error: 'kb_nonce_mismatch' };
  if (typeof p.iat !== 'number' || Math.abs(now - p.iat * 1000) > 120_000) {
    return { ok: false, error: 'stale_kb' };
  }
  const sdPart = [issuerJws, ...discRaw, ''].join('~');
  if (p.sd_hash !== (await disclosureHash(sdPart))) return { ok: false, error: 'kb_sd_hash_mismatch' };

  // 5. revocation (StatusList) — fail closed if the check throws
  if (checkStatus && c.status?.uri) {
    let valid;
    try {
      valid = await checkStatus(c.status.uri, c.status.idx);
    } catch {
      return { ok: false, error: 'status_check_failed' };
    }
    if (valid === false) return { ok: false, error: 'revoked' };
  }

  return { ok: true, iss: c.iss, vct: c.vct, claims };
};
