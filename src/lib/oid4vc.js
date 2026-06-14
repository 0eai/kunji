/**
 * OpenID4VC interop — a thin envelope over kunji's SD-JWT VC core (`vc.js`).
 *
 * kunji's credentials ARE IETF SD-JWT VC + Key-Binding JWT, so interoperating with the standard rails
 * needs no new crypto — only the request/response envelopes:
 *   - OpenID4VCI (issuance): credential offer → token (pre-authorized_code) → credential request with a
 *     holder proof-of-possession JWT. The proof's `jwk` becomes the credential's `cnf.jwk`, so the
 *     per-issuer holder key (`deriveCredentialHolderKey(masterKey, credential_issuer)`) the wallet later
 *     re-derives matches — holder-of-key preserved.
 *   - OpenID4VP (presentation): an authorization request (presentation_definition) → a `vp_token` (the
 *     SD-JWT VC presentation, whose KB-JWT binds aud=client_id, nonce=request nonce) returned via
 *     direct_post. The verifier checks it with the UNCHANGED `verifyCredentialPresentation`.
 *
 * Scope: pre-authorized_code (VCI) + direct_post + presentation_definition (VP), SD-JWT VC only.
 * Deferred (documented in docs/oid4vc.md): authorization_code/PKCE, DPoP, signed request objects /
 * request_uri, DCQL, and the `dc+sd-jwt` format rename (kept as the SD_JWT_VC_FORMAT knob below).
 * No kunji backend is in this path — the wallet talks to the issuer/verifier directly.
 */
import { signJWS, decodeJWS, verifyJWS, okpJwk, pubFromOkpJwk } from './capability';
import { buildPresentation, verifyCredentialPresentation } from './vc';

export const SD_JWT_VC_FORMAT = 'vc+sd-jwt'; // kunji's `typ`; the ecosystem is renaming this to `dc+sd-jwt`
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

// Robust query parse for any scheme (openid-credential-offer://, openid4vp://, https://…?…).
const queryOf = (s) => new URLSearchParams(String(s).includes('?') ? String(s).split('?').slice(1).join('?') : '');

// ── OpenID4VCI — holder side ─────────────────────────────────────────────────

/**
 * Parse a credential offer — the offer object, a `credential_offer=` URI (any scheme), or raw JSON.
 * @returns {{ credentialIssuer, configurationIds: string[], preAuthorizedCode?, txCode? }}
 */
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

/**
 * The OpenID4VCI proof-of-possession JWT (`proof_type: "jwt"`), signed by the holder key. Its `jwk`
 * becomes the issued credential's `cnf.jwk`; `aud` is the credential_issuer; `nonce` is the token
 * endpoint's `c_nonce`. Mechanically the same EdDSA JWS as the capability/KB-JWT.
 */
export const buildProofJwt = ({ holderSecretKey, holderPublicKey, audience, cNonce, now = Date.now() }) =>
  signJWS(
    { typ: 'openid4vci-proof+jwt', alg: 'EdDSA', jwk: okpJwk(holderPublicKey) },
    { aud: audience, iat: Math.floor(now / 1000), nonce: cNonce },
    holderSecretKey,
  );

// ── OpenID4VCI — issuer side ─────────────────────────────────────────────────

/**
 * Verify a holder proof JWT at the credential endpoint: signature by the embedded `jwk`, `aud` ==
 * this issuer, `nonce` == the issued `c_nonce`, fresh `iat`.
 * @returns {{ ok:true, holderJwk } | { ok:false, error }}
 */
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

/** Build a presentation_definition requesting an SD-JWT VC of `vct` disclosing `disclose` claims. */
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

/** Map a presentation_definition input_descriptor → kunji's `{ vct, iss?, disclose }` (PD analogue of parseVcScope). */
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

/** The presentation_submission pairing the response's single SD-JWT VC with the request's PD. */
export const buildPresentationSubmission = (pd) => ({
  id: `kunji-${pd.id}`,
  definition_id: pd.id,
  descriptor_map: [{ id: pd.input_descriptors?.[0]?.id, format: SD_JWT_VC_FORMAT, path: '$' }],
});

// ── OpenID4VP — holder & verifier ────────────────────────────────────────────

/**
 * Parse an OpenID4VP authorization request (direct_post) — a URI of any scheme or a request object.
 * @returns {{ responseType, clientId, nonce, responseMode, responseUri, presentationDefinition }}
 */
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

/** Build a `vp_token`: the SD-JWT VC presentation bound to the verifier (aud=clientId, the request nonce). */
export const buildVpToken = ({ sdjwt, disclose, clientId, nonce, holderSecretKey, now = Date.now() }) =>
  buildPresentation({ sdjwt, disclose, audience: clientId, nonce, holderSecretKey, now });

/**
 * Verify a `vp_token` against the request: the SD-JWT VC + KB-JWT (via the unchanged
 * `verifyCredentialPresentation`, aud=clientId), then the presentation_definition constraints —
 * the requested `vct` matches and every requested claim discloses as `true`.
 * @returns {Promise<{ ok:true, iss, vct, claims } | { ok:false, error }>}
 */
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
