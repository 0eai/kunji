// OpenID4VC interop — a thin envelope over the SD-JWT VC core (Node port of src/lib/oid4vc.js).
// Self-contained JWS helpers (so it doesn't depend on vc.js internals) + the SD-JWT present/verify
// from ./vc.js. kunji credentials ARE IETF SD-JWT VC + KB-JWT, so interop needs no new crypto —
// only the OpenID4VCI (offer→token→credential, holder proof) and OpenID4VP (presentation_definition
// → vp_token via direct_post) envelopes. The issuer demo mints; this RP demo verifies; the
// oid4vc-sim acts as the holder. Byte-identical across the demo copies. See docs/oid4vc.md.
import { ed25519 } from '@noble/curves/ed25519.js';
import { buildPresentation, verifyCredentialPresentation } from './vc.js';

const b64u = {
  fromBytes: (b) => Buffer.from(b).toString('base64url'),
  toBytes: (s) => new Uint8Array(Buffer.from(String(s), 'base64url')),
  fromString: (s) => Buffer.from(String(s), 'utf8').toString('base64url'),
  toString: (s) => Buffer.from(String(s), 'base64url').toString('utf8'),
};
const enc = (s) => new TextEncoder().encode(s);
const signJWS = (header, claims, secretKey) => {
  const input = `${b64u.fromString(JSON.stringify(header))}.${b64u.fromString(JSON.stringify(claims))}`;
  return `${input}.${b64u.fromBytes(ed25519.sign(enc(input), secretKey))}`;
};
const decodeJWS = (token) => {
  const p = String(token).split('.');
  if (p.length !== 3) throw new Error('malformed_jwt');
  return { header: JSON.parse(b64u.toString(p[0])), claims: JSON.parse(b64u.toString(p[1])), input: `${p[0]}.${p[1]}`, sig: b64u.toBytes(p[2]) };
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
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') throw new Error('bad_jwk');
  return b64u.toBytes(jwk.x);
};

export const SD_JWT_VC_FORMAT = 'vc+sd-jwt'; // kunji's `typ`; the ecosystem is renaming this to `dc+sd-jwt`
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const queryOf = (s) => new URLSearchParams(String(s).includes('?') ? String(s).split('?').slice(1).join('?') : '');

// ── OpenID4VCI — holder side ─────────────────────────────────────────────────
export const parseCredentialOffer = (input) => {
  let offer = input;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) offer = JSON.parse(trimmed);
    else {
      const raw = queryOf(trimmed).get('credential_offer');
      if (!raw) throw new Error('no_credential_offer');
      offer = JSON.parse(raw);
    }
  } else if (offer && offer.credential_offer) {
    offer = typeof offer.credential_offer === 'string' ? JSON.parse(offer.credential_offer) : offer.credential_offer;
  }
  const grant = offer?.grants?.[PRE_AUTH_GRANT] || {};
  return {
    credentialIssuer: offer?.credential_issuer,
    configurationIds: offer?.credential_configuration_ids || [],
    preAuthorizedCode: grant['pre-authorized_code'],
    txCode: grant.tx_code,
  };
};

export const buildProofJwt = ({ holderSecretKey, holderPublicKey, audience, cNonce, now = Date.now() }) =>
  signJWS(
    { typ: 'openid4vci-proof+jwt', alg: 'EdDSA', jwk: okpJwk(holderPublicKey) },
    { aud: audience, iat: Math.floor(now / 1000), nonce: cNonce },
    holderSecretKey,
  );

// ── OpenID4VCI — issuer side ─────────────────────────────────────────────────
export const verifyProofJwt = ({ proofJwt, audience, cNonce, now = Date.now() }) => {
  let decoded;
  try {
    decoded = decodeJWS(proofJwt);
  } catch {
    return { ok: false, error: 'malformed_proof' };
  }
  if (decoded.header?.typ !== 'openid4vci-proof+jwt' || decoded.header?.alg !== 'EdDSA') {
    return { ok: false, error: 'bad_proof_header' };
  }
  const jwk = decoded.header.jwk;
  let pub;
  try {
    pub = pubFromOkpJwk(jwk);
  } catch {
    return { ok: false, error: 'bad_proof_jwk' };
  }
  if (!verifyJWS(proofJwt, pub)) return { ok: false, error: 'bad_proof_signature' };
  const p = decoded.claims;
  if (p.aud !== audience) return { ok: false, error: 'proof_audience_mismatch' };
  if (p.nonce !== cNonce) return { ok: false, error: 'proof_nonce_mismatch' };
  if (typeof p.iat !== 'number' || Math.abs(now - p.iat * 1000) > 300_000) return { ok: false, error: 'stale_proof' };
  return { ok: true, holderJwk: jwk };
};

// ── OpenID4VP — presentation_definition ↔ kunji vc query ─────────────────────
export const buildPresentationDefinition = ({ vct, disclose = [] }) => ({
  id: vct,
  input_descriptors: [
    {
      id: vct,
      format: { [SD_JWT_VC_FORMAT]: { 'sd-jwt_alg_values': ['EdDSA'], 'kb-jwt_alg_values': ['EdDSA'] } },
      constraints: {
        fields: [
          { path: ['$.vct'], filter: { type: 'string', const: vct } },
          ...disclose.map((c) => ({ path: [`$.${c}`] })),
        ],
      },
    },
  ],
});

export const pdToVcQuery = (pd) => {
  const fields = pd?.input_descriptors?.[0]?.constraints?.fields || [];
  let vct;
  let iss;
  const disclose = [];
  for (const f of fields) {
    const path = (f.path && f.path[0]) || '';
    const key = path.replace(/^\$\./, '');
    if (key === 'vct') vct = f.filter?.const;
    else if (key === 'iss') iss = f.filter?.const;
    else if (key) disclose.push(key);
  }
  return { vct, iss, disclose };
};

export const buildPresentationSubmission = (pd) => ({
  id: `kunji-${pd.id}`,
  definition_id: pd.id,
  descriptor_map: [{ id: pd.input_descriptors?.[0]?.id, format: SD_JWT_VC_FORMAT, path: '$' }],
});

// ── OpenID4VP — holder & verifier ────────────────────────────────────────────
export const parseAuthorizationRequest = (input) => {
  let get;
  if (typeof input === 'string') {
    const q = queryOf(input);
    get = (k) => q.get(k);
  } else {
    get = (k) => input?.[k];
  }
  const pd = get('presentation_definition');
  return {
    responseType: get('response_type'),
    clientId: get('client_id'),
    nonce: get('nonce'),
    state: get('state'), // echoed back in the direct_post so the verifier can correlate the response
    responseMode: get('response_mode'),
    responseUri: get('response_uri'),
    presentationDefinition: typeof pd === 'string' ? JSON.parse(pd) : pd,
  };
};

export const buildVpToken = ({ sdjwt, disclose, clientId, nonce, holderSecretKey, now = Date.now() }) =>
  buildPresentation({ sdjwt, disclose, audience: clientId, nonce, holderSecretKey, now });

export const verifyVpToken = async ({
  vpToken,
  presentationDefinition,
  getIssuerKeys,
  checkStatus,
  clientId,
  nonce,
  now = Date.now(),
}) => {
  const r = await verifyCredentialPresentation({
    presentation: vpToken,
    getIssuerKeys,
    checkStatus,
    audience: clientId,
    nonce,
    now,
  });
  if (!r.ok) return r;
  const q = pdToVcQuery(presentationDefinition);
  if (q.vct && r.vct !== q.vct) return { ok: false, error: 'vct_mismatch' };
  if (q.iss && r.iss !== q.iss) return { ok: false, error: 'issuer_mismatch' };
  for (const c of q.disclose) {
    if (r.claims?.[c] !== true) return { ok: false, error: 'predicate_failed' };
  }
  return r;
};
