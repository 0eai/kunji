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
 * Scope: pre-authorized_code + authorization_code/PKCE (VCI) + direct_post / direct_post.jwt (VP). Both
 * presentation_definition and DCQL queries; unsigned + signed (JAR) requests delivered inline or by
 * `request_uri`. Verifier auth dispatches on the client_id scheme: HTTPS-anchored `.well-known` (default),
 * `did:jwk`/`did:web`, and `x509_san_dns` (DID/x509 verifiers injected so this stays EdDSA-pure). Both
 * `vc+sd-jwt` and the renamed `dc+sd-jwt` are accepted. DPoP (RFC 9449) sender-constrains the token leg.
 * Deferred (docs/oid4vc.md): the encrypted *request* (verifier→wallet) + the authorization_code wallet UI.
 * No kunji backend is in this path — the wallet talks to the issuer/verifier directly.
 */
import { signJWS, decodeJWS, verifyJWS, okpJwk, pubFromOkpJwk } from './capability';
import { buildPresentation, verifyCredentialPresentation } from './vc';
import { buildBbsPresentation, verifyBbsPresentation, encodeBbsPresentation, decodeBbsPresentation, isBbsPresentation } from './vcBbs';

export const SD_JWT_VC_FORMAT = 'vc+sd-jwt'; // EMIT default; the ecosystem renamed this to `dc+sd-jwt`
export const SD_JWT_VC_FORMATS = ['vc+sd-jwt', 'dc+sd-jwt']; // ACCEPT both (back-compat rename) [dc+sd-jwt]
export const BBS_VC_FORMAT = 'vc+bbs'; // the unlinkable (v3) credential format — verified-credentials.md §7
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const AUTH_CODE_GRANT = 'authorization_code';

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
  const authGrant = offer?.grants?.[AUTH_CODE_GRANT];
  return {
    credentialIssuer: offer?.credential_issuer,
    configurationIds: offer?.credential_configuration_ids || [],
    preAuthorizedCode: grant['pre-authorized_code'],
    txCode: grant.tx_code,
    // The authorization_code grant (omitted when absent → existing pre-auth callers untouched).
    authorizationCode: authGrant
      ? { issuerState: authGrant.issuer_state, authorizationServer: authGrant.authorization_server }
      : undefined,
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

// ── DPoP (RFC 9449) — sender-constrained access token on the token + credential leg ──
// kunji pins EdDSA everywhere (capability / KB-JWT / proof), so the DPoP proof key is Ed25519 too — a
// deliberate deviation from the RFC's usual ES256 (one curve, one verify path). Freshness is the same
// ±300s iat window as verifyProofJwt; replay (`jti`) detection is the SERVER's job, like the other verifiers.
const dpopB64u = (bytes) => {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const dpopSha256 = async (str) => new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)));
const normalizeHtu = (u) => {
  try {
    const x = new URL(u);
    return `${x.origin}${x.pathname}`; // RFC 9449: compare htu without query/fragment
  } catch {
    return String(u || '');
  }
};
const randomDpopJti = () => {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return dpopB64u(b);
};

/** RFC 7638 JWK thumbprint of an OKP Ed25519 JWK → base64url(SHA-256(canonical {crv,kty,x})). */
export const jwkThumbprint = async (jwk) =>
  dpopB64u(await dpopSha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })));

/**
 * Build a DPoP proof JWS (`typ:'dpop+jwt'`, embedded `jwk`). Claims: `htu` (URL, no query/fragment),
 * `htm` (method), `iat`, random `jti`, plus `ath` (base64url-SHA-256 of the access token) when bound and
 * `nonce` when the server issued a DPoP-Nonce.
 */
export const buildDpopProof = async ({ htu, htm, accessToken, nonce, holderSecretKey, holderPublicKey, now = Date.now() }) => {
  const header = { alg: 'EdDSA', typ: 'dpop+jwt', jwk: okpJwk(holderPublicKey) };
  const claims = {
    htu: normalizeHtu(htu),
    htm: String(htm || '').toUpperCase(),
    iat: Math.floor(now / 1000),
    jti: randomDpopJti(),
    ...(accessToken ? { ath: dpopB64u(await dpopSha256(accessToken)) } : {}),
    ...(nonce ? { nonce } : {}),
  };
  return signJWS(header, claims, holderSecretKey);
};

/**
 * Verify a DPoP proof: typ/alg, the embedded-jwk signature, `htu`/`htm` match, `iat` freshness, and `ath`
 * == SHA-256(access token) when an `accessToken` is given. Returns the key thumbprint `jkt` (to bind/compare
 * `cnf.jkt`) and `jti` (for the server's replay cache).
 * @returns {Promise<{ ok:true, jkt, jti } | { ok:false, error }>}
 */
export const verifyDpopProof = async ({ dpop, htu, htm, accessToken, now = Date.now() }) => {
  let decoded;
  try {
    decoded = decodeJWS(dpop);
  } catch {
    return { ok: false, error: 'malformed_dpop' };
  }
  if (decoded.header?.typ !== 'dpop+jwt' || decoded.header?.alg !== 'EdDSA') return { ok: false, error: 'bad_dpop_header' };
  let pub;
  try {
    pub = pubFromOkpJwk(decoded.header.jwk);
  } catch {
    return { ok: false, error: 'bad_dpop_jwk' };
  }
  if (!verifyJWS(dpop, pub)) return { ok: false, error: 'bad_dpop_signature' };
  const p = decoded.claims;
  if (p.htu !== normalizeHtu(htu)) return { ok: false, error: 'dpop_htu_mismatch' };
  if (p.htm !== String(htm || '').toUpperCase()) return { ok: false, error: 'dpop_htm_mismatch' };
  if (typeof p.iat !== 'number' || Math.abs(now - p.iat * 1000) > 300_000) return { ok: false, error: 'stale_dpop' };
  if (accessToken && p.ath !== dpopB64u(await dpopSha256(accessToken))) return { ok: false, error: 'dpop_ath_mismatch' };
  return { ok: true, jkt: await jwkThumbprint(decoded.header.jwk), jti: p.jti };
};

// ── OpenID4VCI — authorization_code grant + PKCE (S256) ──────────────────────
// A second issuance path alongside pre-authorized_code (the default). PKCE uses S256 only. The lib +
// demos + headless sim prove the flow end-to-end; the wallet UI is deferred (kunji is a QR/no-redirect
// wallet — there's no authorization-server redirect/custom-scheme return). Reuses dpopB64u/dpopSha256.

/** A PKCE code_verifier (RFC 7636): 43 chars of base64url(32 random bytes). */
export const generateCodeVerifier = () => {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return dpopB64u(b);
};
/** code_challenge = base64url(SHA-256(ascii(code_verifier))) for `code_challenge_method=S256`. */
export const computeCodeChallenge = async (codeVerifier) => dpopB64u(await dpopSha256(codeVerifier));
/** Generate a PKCE pair (S256). */
export const generatePkce = async () => {
  const codeVerifier = generateCodeVerifier();
  return { codeVerifier, codeChallenge: await computeCodeChallenge(codeVerifier), codeChallengeMethod: 'S256' };
};
/** Issuer side: a code_verifier matches a stored code_challenge (S256). */
export const verifyPkce = async ({ codeVerifier, codeChallenge }) =>
  typeof codeVerifier === 'string' && (await computeCodeChallenge(codeVerifier)) === codeChallenge;

/**
 * Build the holder's authorization request to the issuer's authorization endpoint. Returns `{ url, params }`
 * (no browser needed — the sim drives it). `authorization_details` is the OID4VCI-preferred way to ask for
 * a configuration; `code_challenge`/S256 carry PKCE; `state` is the holder's CSRF check on the redirect.
 */
export const buildAuthorizationRequest = ({
  authorizationEndpoint,
  clientId,
  redirectUri,
  codeChallenge,
  state,
  issuerState,
  credentialIssuer,
  configurationId,
  scope,
}) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    authorization_details: JSON.stringify([
      { type: 'openid_credential', credential_configuration_id: configurationId, ...(credentialIssuer ? { locations: [credentialIssuer] } : {}) },
    ]),
    ...(scope ? { scope } : {}),
    ...(issuerState ? { issuer_state: issuerState } : {}),
  });
  return { url: `${authorizationEndpoint}?${params.toString()}`, params };
};

/**
 * Resolve the issuer's authorization endpoint: read the issuer metadata → its authorization server →
 * that server's `/.well-known/oauth-authorization-server`. `fetchImpl` is injectable for tests.
 */
export const resolveAuthorizationEndpoint = async (credentialIssuer, { fetchImpl = fetch } = {}) => {
  const issuer = String(credentialIssuer).replace(/\/$/, '');
  const meta = await (await fetchImpl(`${issuer}/.well-known/openid-credential-issuer`)).json();
  const authServer = String((meta.authorization_servers && meta.authorization_servers[0]) || issuer).replace(/\/$/, '');
  const as = await (await fetchImpl(`${authServer}/.well-known/oauth-authorization-server`)).json();
  return {
    authorizationServer: authServer,
    authorizationEndpoint: as.authorization_endpoint || `${authServer}/authorize`,
    tokenEndpoint: as.token_endpoint || `${issuer}/token`,
  };
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
  const descriptor = pd?.input_descriptors?.[0];
  const fields = descriptor?.constraints?.fields || [];
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
  const format = descriptor?.format ? Object.keys(descriptor.format)[0] : undefined;
  return { vct, iss, disclose, format };
};

/** The presentation_submission pairing the response's single SD-JWT VC with the request's PD. */
export const buildPresentationSubmission = (pd) => ({
  id: `kunji-${pd.id}`,
  definition_id: pd.id,
  descriptor_map: [{ id: pd.input_descriptors?.[0]?.id, format: SD_JWT_VC_FORMAT, path: '$' }],
});

// ── OpenID4VP — DCQL (the presentation_definition successor, OpenID4VP 1.0) ───

/** Build a DCQL query requesting a credential of `vct` (SD-JWT by default, or `vc+bbs`) disclosing `disclose`. */
export const buildDcqlQuery = ({ id = 'cred', vct, disclose = [], format = SD_JWT_VC_FORMAT }) => ({
  credentials: [{ id, format, meta: { vct_values: [vct] }, claims: disclose.map((c) => ({ path: [c] })) }],
});

/** Map a DCQL credential query → kunji's `{ id, vct, iss?, disclose }` (the DCQL analogue of pdToVcQuery). */
export const dcqlToVcQuery = (dcql) => {
  const c = dcql?.credentials?.[0] || {};
  const disclose = (c.claims || [])
    .map((cl) => (Array.isArray(cl.path) ? cl.path[cl.path.length - 1] : undefined))
    .filter(Boolean);
  return { id: c.id, vct: c.meta?.vct_values?.[0], iss: undefined, disclose, format: c.format };
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
      clientMetadata: asObj(c.client_metadata), // carries the verifier's enc key for direct_post.jwt
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
    clientMetadata: asObj(get('client_metadata')),
  };
};

/**
 * Verifier side: sign an authorization request (JAR, request-by-value). `params` are the authz fields
 * (client_id, response_type, response_mode, response_uri, nonce, state, and a `presentation_definition`
 * or `dcql_query`); the wallet delivers it as `openid4vp://?client_id=<host>&request=<this JWS>`.
 */
// Hosts where http:// is allowed (local dev) — same posture as the wallet's callback/issuer guards.
const isLoopbackHost = (h) => h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';

/**
 * Resolve an OpenID4VP request that may be by-REFERENCE: if the input carries `request_uri` (and no inline
 * `request`), fetch the signed request object from it (HTTPS-only except loopback) and parse that. The
 * fetch host is UNTRUSTED — `verifyRequestObject` still checks the signature, so a forged `request_uri`
 * body can't impersonate a verifier. Otherwise (inline/unsigned) just `parseAuthorizationRequest`.
 * `fetchImpl` is injectable for tests. [request_uri by-reference]
 */
export const resolveAuthorizationRequest = async (input, { fetchImpl = fetch } = {}) => {
  const get = typeof input === 'string' ? (k) => queryOf(input).get(k) : (k) => input?.[k];
  const requestUri = get('request_uri');
  if (requestUri && !get('request')) {
    let u;
    try {
      u = new URL(requestUri);
    } catch {
      throw new Error('bad_request_uri');
    }
    if (u.protocol !== 'https:' && !isLoopbackHost(u.hostname)) throw new Error('request_uri_not_https');
    const resp = await fetchImpl(requestUri);
    if (!resp.ok) throw new Error('request_uri_unreachable');
    const requestJwt = (await resp.text()).trim();
    return parseAuthorizationRequest({ client_id: get('client_id'), request: requestJwt });
  }
  return parseAuthorizationRequest(input);
};

export const buildSignedAuthorizationRequest = (verifierSecretKey, { kid, params, ttlSeconds = 300, now = Date.now() }) => {
  const iat = Math.floor(now / 1000);
  const claims = { ...params, iat, exp: iat + Math.max(1, Math.floor(ttlSeconds)) };
  return signJWS({ alg: 'EdDSA', typ: 'oauth-authz-req+jwt', kid }, claims, verifierSecretKey);
};

/**
 * Classify an OpenID4VP `client_id` by scheme: `did:*` (key from the DID), `x509_san_dns:<dns>` (key from
 * an x5c cert whose SAN matches), or the default HTTPS-anchored origin (key from its `.well-known`). A bare
 * origin stays the back-compat default.
 */
export const parseClientIdScheme = (clientId) => {
  const s = String(clientId || '');
  if (s.startsWith('did:')) return { scheme: 'did', value: s };
  if (s.startsWith('x509_san_dns:')) return { scheme: 'x509_san_dns', value: s.slice('x509_san_dns:'.length) };
  return { scheme: 'https', value: s };
};

/**
 * Wallet side: verify a signed request object against the verifier's published key. `getVerifierKeys(cid)`
 * resolves the verifier's OKP keys (from `https://<client_id>/.well-known/kunji-verifier.json` — injectable
 * so tests run offline). Confirms typ/alg, the signature, the signed `client_id` matches the outer one the
 * wallet used to find the key, and freshness. Proves the verifier controls its HTTPS origin.
 * @returns {Promise<{ ok:true, clientId } | { ok:false, error }>}
 */
export const verifyRequestObject = async ({ requestJwt, getVerifierKeys, resolveDidKey, verifyX509, trustAnchors, clientId, now = Date.now() }) => {
  let decoded;
  try {
    decoded = decodeJWS(requestJwt);
  } catch {
    return { ok: false, error: 'malformed_request' };
  }
  if (decoded.header?.typ !== 'oauth-authz-req+jwt') return { ok: false, error: 'bad_request_header' };
  const cid = clientId || decoded.claims?.client_id;
  if (!cid) return { ok: false, error: 'no_client_id' };
  if (clientId && decoded.claims?.client_id && decoded.claims.client_id !== clientId) {
    return { ok: false, error: 'client_id_mismatch' };
  }
  // Dispatch by client_id scheme. Default (bare/https origin) is the existing HTTPS-anchored `.well-known`
  // scheme (EdDSA). did:* resolves an OKP key (EdDSA). x509_san_dns verifies an ES256 JWS against an x5c
  // chain (delegated to the injected verifyX509 — keeps this module EdDSA-pure + free of the DER parser).
  const scheme = parseClientIdScheme(cid);
  if (scheme.scheme === 'x509_san_dns') {
    if (decoded.header?.alg !== 'ES256') return { ok: false, error: 'bad_request_header' };
    if (!verifyX509) return { ok: false, error: 'unsupported_client_id_scheme' };
    const x5c = decoded.header?.x5c;
    if (!Array.isArray(x5c) || !x5c.length) return { ok: false, error: 'no_x5c' };
    const xr = await verifyX509({ requestJwt, x5c, dnsName: scheme.value, trustAnchors, now });
    if (!xr.ok) return xr;
  } else {
    if (decoded.header?.alg !== 'EdDSA') return { ok: false, error: 'bad_request_header' };
    let pub;
    if (scheme.scheme === 'did') {
      if (!resolveDidKey) return { ok: false, error: 'unsupported_client_id_scheme' };
      let jwk;
      try {
        jwk = await resolveDidKey(cid, { kid: decoded.header?.kid });
      } catch (e) {
        return { ok: false, error: e?.message || 'did_unresolved' };
      }
      try {
        pub = pubFromOkpJwk(jwk);
      } catch {
        return { ok: false, error: 'bad_verifier_key' };
      }
    } else {
      let keys;
      try {
        keys = await getVerifierKeys(cid);
      } catch {
        return { ok: false, error: 'verifier_unresolved' };
      }
      const jwk = (keys || []).find((k) => k.kid === decoded.header.kid) || (keys || [])[0];
      try {
        pub = pubFromOkpJwk(jwk);
      } catch {
        return { ok: false, error: 'bad_verifier_key' };
      }
    }
    if (!verifyJWS(requestJwt, pub)) return { ok: false, error: 'bad_request_signature' };
  }
  const p = decoded.claims || {};
  if (typeof p.exp === 'number' && now > p.exp * 1000) return { ok: false, error: 'request_expired' };
  if (typeof p.iat === 'number' && now < p.iat * 1000 - 120_000) return { ok: false, error: 'request_not_yet_valid' };
  return { ok: true, clientId: cid, scheme: scheme.scheme };
};

/** Build a `vp_token`: the SD-JWT VC presentation bound to the verifier (aud=clientId, the request nonce). */
export const buildVpToken = ({ sdjwt, disclose, clientId, nonce, holderSecretKey, now = Date.now() }) =>
  buildPresentation({ sdjwt, disclose, audience: clientId, nonce, holderSecretKey, now });

/**
 * Build a `vc+bbs` vp_token: an unlinkable BBS presentation (a fresh randomized proof) bound to the
 * verifier (aud=clientId, the request nonce), serialized as a tagged string. `issuerPublicKey` is the
 * issuer's BBS key. No holder secret — the proof is derived from the credential itself.
 */
export const buildBbsVpToken = async ({ credential, disclose, clientId, nonce, issuerPublicKey, holderSecret }) =>
  encodeBbsPresentation(await buildBbsPresentation({ credential, disclose, audience: clientId, nonce, issuerPublicKey, holderSecret }));

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
  getIssuerBbsKey,
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
  // Enforce the requested format (default SD-JWT): a request must not silently accept the other format —
  // e.g. an SD-JWT request (expecting holder binding) accepting a non-holder-bound BBS proof. [S25]
  const isBbs = isBbsPresentation(presentation);
  // Reject a genuinely-unknown requested format up front; a missing format still routes to SD-JWT
  // (today's behavior), and `dc+sd-jwt` is accepted alongside `vc+sd-jwt`. [dc+sd-jwt]
  if (q.format && q.format !== BBS_VC_FORMAT && !SD_JWT_VC_FORMATS.includes(q.format)) {
    return { ok: false, error: 'unsupported_format' };
  }
  if ((q.format === BBS_VC_FORMAT) !== isBbs) return { ok: false, error: 'format_mismatch' };
  // Dispatch by format: a `bbs~`-tagged token is an unlinkable BBS presentation (v3); otherwise SD-JWT.
  const r = isBbs
    ? await verifyBbsPresentation({ presentation: decodeBbsPresentation(presentation), getIssuerBbsKey, audience: clientId, nonce, now })
    : await verifyCredentialPresentation({ presentation, getIssuerKeys, checkStatus, audience: clientId, nonce, now });
  if (!r.ok) return r;
  if (q.vct && r.vct !== q.vct) return { ok: false, error: 'vct_mismatch' };
  if (q.iss && r.iss !== q.iss) return { ok: false, error: 'issuer_mismatch' };
  for (const c of q.disclose) {
    if (r.claims?.[c] !== true) return { ok: false, error: 'predicate_failed' };
  }
  return r;
};
