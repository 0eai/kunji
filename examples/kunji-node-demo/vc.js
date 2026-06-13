// Verified credentials — SD-JWT VC (Node port of src/lib/vc.js).
// Self-contained: same format + checks, so a credential minted/presented by the kunji wallet
// verifies here byte-for-byte. The issuer demo mints; this RP demo verifies; the wallet-sim
// (holder) presents. Mirrors the capability.js port style. See docs/verified-credentials.md.
import { createHash, randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

const b64u = {
  fromBytes: (b) => Buffer.from(b).toString('base64url'),
  toBytes: (s) => new Uint8Array(Buffer.from(String(s), 'base64url')),
  fromString: (s) => Buffer.from(String(s), 'utf8').toString('base64url'),
  toString: (s) => Buffer.from(String(s), 'base64url').toString('utf8'),
};
const enc = (s) => new TextEncoder().encode(s);

// --- EdDSA compact JWS --------------------------------------------------------
const signJWS = (header, claims, secretKey) => {
  const input = `${b64u.fromString(JSON.stringify(header))}.${b64u.fromString(JSON.stringify(claims))}`;
  return `${input}.${b64u.fromBytes(ed25519.sign(enc(input), secretKey))}`;
};
const decodeJWS = (token) => {
  const p = String(token).split('.');
  if (p.length !== 3) throw new Error('malformed_jwt');
  return {
    header: JSON.parse(b64u.toString(p[0])),
    claims: JSON.parse(b64u.toString(p[1])),
    input: `${p[0]}.${p[1]}`,
    sig: b64u.toBytes(p[2]),
  };
};
const verifyJWS = (token, pub) => {
  try {
    const d = decodeJWS(token);
    return ed25519.verify(d.sig, enc(d.input), pub) ? { header: d.header, claims: d.claims } : null;
  } catch {
    return null;
  }
};
const okpJwk = (pub) => ({ kty: 'OKP', crv: 'Ed25519', x: b64u.fromBytes(pub) });
const pubFromOkpJwk = (jwk) => {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('bad_jwk');
  }
  return b64u.toBytes(jwk.x);
};

// --- SD-JWT helpers -----------------------------------------------------------
export const disclosureHash = (disclosureStr) =>
  b64u.fromBytes(createHash('sha256').update(enc(disclosureStr)).digest());
const randomSalt = () => b64u.fromBytes(randomBytes(16));

/** Build the holder JWK to hand the issuer at request time (binds the credential to the holder key). */
export const holderJwkFor = (holderPublicKey) => okpJwk(holderPublicKey);

// --- Issuer: mint an SD-JWT VC -----------------------------------------------
export const mintCredential = (
  issuerSecretKey,
  { kid, iss, vct, claims, holderJwk, status, ttlSeconds, now = Date.now() },
) => {
  const iat = Math.floor(now / 1000);
  const exp = iat + Math.max(1, Math.floor(ttlSeconds || 0));
  const disclosures = [];
  const _sd = [];
  for (const [name, value] of Object.entries(claims || {})) {
    const disc = b64u.fromString(JSON.stringify([randomSalt(), name, value]));
    disclosures.push(disc);
    _sd.push(disclosureHash(disc));
  }
  const header = { alg: 'EdDSA', typ: 'vc+sd-jwt', kid };
  const payload = { iss, vct, iat, exp, cnf: { jwk: holderJwk }, _sd_alg: 'sha-256', _sd };
  if (status) payload.status = status;
  return [signJWS(header, payload, issuerSecretKey), ...disclosures, ''].join('~');
};

// --- Holder: parse + present --------------------------------------------------
export const parseSdJwt = (sdjwt) => {
  const parts = String(sdjwt).split('~');
  const issuerJws = parts[0];
  const { header: issuerHeader, claims: issuerClaims } = decodeJWS(issuerJws);
  const disclosures = parts
    .slice(1)
    .filter((p) => p.length > 0)
    .map((raw) => {
      const [salt, name, value] = JSON.parse(b64u.toString(raw));
      return { raw, salt, name, value };
    });
  return { issuerJws, issuerHeader, issuerClaims, disclosures };
};

const buildKeyBindingJwt = ({ holderSecretKey, audience, nonce, sdHash, now = Date.now() }) =>
  signJWS(
    { typ: 'kb+jwt', alg: 'EdDSA' },
    { aud: audience, nonce, iat: Math.floor(now / 1000), sd_hash: sdHash },
    holderSecretKey,
  );

export const buildPresentation = ({ sdjwt, disclose, audience, nonce, holderSecretKey, now = Date.now() }) => {
  const parsed = parseSdJwt(sdjwt);
  const want = new Set(disclose || []);
  const selected = parsed.disclosures.filter((d) => want.has(d.name)).map((d) => d.raw);
  const sdPart = [parsed.issuerJws, ...selected, ''].join('~');
  return sdPart + buildKeyBindingJwt({ holderSecretKey, audience, nonce, sdHash: disclosureHash(sdPart), now });
};

// --- Verifier (RP-side) -------------------------------------------------------
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

  if (typeof c.exp !== 'number' || now > c.exp * 1000) return { ok: false, error: 'credential_expired' };

  const sdSet = new Set(Array.isArray(c._sd) ? c._sd : []);
  const claims = {};
  for (const raw of discRaw) {
    if (!sdSet.has(disclosureHash(raw))) return { ok: false, error: 'disclosure_not_in_sd' };
    let parsed;
    try {
      parsed = JSON.parse(b64u.toString(raw));
    } catch {
      return { ok: false, error: 'bad_disclosure' };
    }
    claims[parsed[1]] = parsed[2];
  }

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
  if (p.sd_hash !== disclosureHash(sdPart)) return { ok: false, error: 'kb_sd_hash_mismatch' };

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
