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
 * Scope: pre-authorized_code (VCI) + direct_post (VP). Both presentation_definition and DCQL queries,
 * and both unsigned and signed (JAR) authorization requests — a signed request is verified against the
 * verifier's key published at its own `.well-known/kunji-verifier.json` (an HTTPS-anchored client_id
 * scheme, mirroring the issuer-key model), so the verifier identity is cryptographically proven.
 * Deferred (documented in docs/oid4vc.md): authorization_code/PKCE, DPoP, `request_uri` by-reference,
 * x509/DID client_id schemes, and the `dc+sd-jwt` format rename (kept as the SD_JWT_VC_FORMAT knob below).
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

// ── OpenID4VP — DCQL (the presentation_definition successor, OpenID4VP 1.0) ───

/** Build a DCQL query requesting an SD-JWT VC of `vct` disclosing `disclose` claims. */
export const buildDcqlQuery = ({ id = 'cred', vct, disclose = [] }) => ({
  credentials: [
    { id, format: SD_JWT_VC_FORMAT, meta: { vct_values: [vct] }, claims: disclose.map((c) => ({ path: [c] })) },
  ],
});

/** Map a DCQL credential query → kunji's `{ id, vct, iss?, disclose }` (the DCQL analogue of pdToVcQuery). */
export const dcqlToVcQuery = (dcql) => {
  const c = dcql?.credentials?.[0] || {};
  const disclose = (c.claims || [])
    .map((cl) => (Array.isArray(cl.path) ? cl.path[cl.path.length - 1] : undefined))
    .filter(Boolean);
  return { id: c.id, vct: c.meta?.vct_values?.[0], iss: undefined, disclose };
};

/** Unified view of either query form on a parsed request → `{ kind:'dcql'|'pd', id?, vct, iss?, disclose }`. */
export const requestQuery = (request) => {
  if (request?.dcqlQuery) return { kind: 'dcql', ...dcqlToVcQuery(request.dcqlQuery) };
  return { kind: 'pd', id: request?.presentationDefinition?.id, ...pdToVcQuery(request?.presentationDefinition) };
};

/**
 * Build the direct_post body for either query form. DCQL (OpenID4VP 1.0) → `vp_token` keyed by the
 * credential id, no presentation_submission; presentation_definition → the bare `vp_token` + a submission.
 */
export const buildVpResponse = ({ request, presentation }) => {
  const q = requestQuery(request);
  if (q.kind === 'dcql') return { vp_token: { [q.id]: presentation }, state: request.state };
  return {
    vp_token: presentation,
    presentation_submission: buildPresentationSubmission(request.presentationDefinition),
    state: request.state,
  };
};

// ── OpenID4VP — holder & verifier ────────────────────────────────────────────

const asObj = (v) => (typeof v === 'string' ? JSON.parse(v) : v);

/**
 * Parse an OpenID4VP authorization request (direct_post) — a URI of any scheme or a request object.
 * A JAR `request` (a signed JWS, request-by-value) is decoded for its params and flagged `signed:true`
 * (verify it with `verifyRequestObject` before trusting it). Carries either a `presentation_definition`
 * or a `dcqlQuery`.
 */
export const parseAuthorizationRequest = (input) => {
  let get;
  if (typeof input === 'string') {
    const q = queryOf(input);
    get = (k) => q.get(k);
  } else {
    get = (k) => input?.[k];
  }
  const requestJwt = get('request');
  if (requestJwt) {
    let c = {};
    try {
      c = decodeJWS(requestJwt).claims || {};
    } catch {
      c = {};
    }
    return {
      signed: true,
      requestJwt,
      responseType: c.response_type,
      clientId: get('client_id') || c.client_id, // outer client_id (used to find the key) ?? the signed one
      nonce: c.nonce,
      state: c.state,
      responseMode: c.response_mode,
      responseUri: c.response_uri,
      presentationDefinition: asObj(c.presentation_definition),
      dcqlQuery: asObj(c.dcql_query),
    };
  }
  return {
    signed: false,
    responseType: get('response_type'),
    clientId: get('client_id'),
    nonce: get('nonce'),
    state: get('state'), // echoed back in the direct_post so the verifier can correlate the response
    responseMode: get('response_mode'),
    responseUri: get('response_uri'),
    presentationDefinition: asObj(get('presentation_definition')),
    dcqlQuery: asObj(get('dcql_query')),
  };
};

/**
 * Verifier side: sign an authorization request (JAR, request-by-value). `params` are the authz fields
 * (client_id, response_type, response_mode, response_uri, nonce, state, and a `presentation_definition`
 * or `dcql_query`); the wallet delivers it as `openid4vp://?client_id=<host>&request=<this JWS>`.
 */
export const buildSignedAuthorizationRequest = (verifierSecretKey, { kid, params, ttlSeconds = 300, now = Date.now() }) => {
  const iat = Math.floor(now / 1000);
  const claims = { ...params, iat, exp: iat + Math.max(1, Math.floor(ttlSeconds)) };
  return signJWS({ alg: 'EdDSA', typ: 'oauth-authz-req+jwt', kid }, claims, verifierSecretKey);
};

/**
 * Wallet side: verify a signed request object against the verifier's published key. `getVerifierKeys(cid)`
 * resolves the verifier's OKP keys (from `https://<client_id>/.well-known/kunji-verifier.json` — injectable
 * so tests run offline). Confirms typ/alg, the signature, the signed `client_id` matches the outer one the
 * wallet used to find the key, and freshness. Proves the verifier controls its HTTPS origin.
 * @returns {Promise<{ ok:true, clientId } | { ok:false, error }>}
 */
export const verifyRequestObject = async ({ requestJwt, getVerifierKeys, clientId, now = Date.now() }) => {
  let decoded;
  try {
    decoded = decodeJWS(requestJwt);
  } catch {
    return { ok: false, error: 'malformed_request' };
  }
  if (decoded.header?.typ !== 'oauth-authz-req+jwt' || decoded.header?.alg !== 'EdDSA') {
    return { ok: false, error: 'bad_request_header' };
  }
  const cid = clientId || decoded.claims?.client_id;
  if (!cid) return { ok: false, error: 'no_client_id' };
  if (clientId && decoded.claims?.client_id && decoded.claims.client_id !== clientId) {
    return { ok: false, error: 'client_id_mismatch' };
  }
  let keys;
  try {
    keys = await getVerifierKeys(cid);
  } catch {
    return { ok: false, error: 'verifier_unresolved' };
  }
  const jwk = (keys || []).find((k) => k.kid === decoded.header.kid) || (keys || [])[0];
  let pub;
  try {
    pub = pubFromOkpJwk(jwk);
  } catch {
    return { ok: false, error: 'bad_verifier_key' };
  }
  if (!verifyJWS(requestJwt, pub)) return { ok: false, error: 'bad_request_signature' };
  const p = decoded.claims || {};
  if (typeof p.exp === 'number' && now > p.exp * 1000) return { ok: false, error: 'request_expired' };
  if (typeof p.iat === 'number' && now < p.iat * 1000 - 120_000) return { ok: false, error: 'request_not_yet_valid' };
  return { ok: true, clientId: cid };
};

/** Build a `vp_token`: the SD-JWT VC presentation bound to the verifier (aud=clientId, the request nonce). */
export const buildVpToken = ({ sdjwt, disclose, clientId, nonce, holderSecretKey, now = Date.now() }) =>
  buildPresentation({ sdjwt, disclose, audience: clientId, nonce, holderSecretKey, now });

/**
 * Verify a `vp_token` against the request: the SD-JWT VC + KB-JWT (via the unchanged
 * `verifyCredentialPresentation`, aud=clientId), then the query constraints — the requested `vct`
 * matches and every requested claim discloses as `true`. Accepts either a `presentationDefinition`
 * (vp_token is the bare SD-JWT string) or a `dcqlQuery` (vp_token is an object keyed by the credential id).
 * @returns {Promise<{ ok:true, iss, vct, claims } | { ok:false, error }>}
 */
export const verifyVpToken = async ({
  vpToken,
  presentationDefinition,
  dcqlQuery,
  getIssuerKeys,
  checkStatus,
  clientId,
  nonce,
  now = Date.now(),
}) => {
  const q = dcqlQuery
    ? { kind: 'dcql', ...dcqlToVcQuery(dcqlQuery) }
    : { kind: 'pd', ...pdToVcQuery(presentationDefinition) };
  const presentation = q.kind === 'dcql' ? (vpToken && typeof vpToken === 'object' ? vpToken[q.id] : undefined) : vpToken;
  if (!presentation || typeof presentation !== 'string') return { ok: false, error: 'missing_vp_token' };
  const r = await verifyCredentialPresentation({
    presentation,
    getIssuerKeys,
    checkStatus,
    audience: clientId,
    nonce,
    now,
  });
  if (!r.ok) return r;
  if (q.vct && r.vct !== q.vct) return { ok: false, error: 'vct_mismatch' };
  if (q.iss && r.iss !== q.iss) return { ok: false, error: 'issuer_mismatch' };
  for (const c of q.disclose) {
    if (r.claims?.[c] !== true) return { ok: false, error: 'predicate_failed' };
  }
  return r;
};
