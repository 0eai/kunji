// OpenID4VCI issuance for the kunji issuer demo — the standard envelope around the existing `issue()`.
//
// Flow (pre-authorized_code grant):
//   GET  /credential-offer            → mint a pre-auth code, return the credential_offer (+ offer URI)
//   POST /token                       → exchange the pre-auth code for an access_token + c_nonce
//   POST /credential                  → with a holder proof JWT (nonce=c_nonce) → the SD-JWT VC
//   GET  /.well-known/openid-credential-issuer  → issuer metadata
//   GET  /.well-known/oauth-authorization-server → token endpoint metadata
//
// The proof JWT's `jwk` becomes the credential's `cnf.jwk`, so the holder key the wallet re-derives on
// presentation matches — holder-of-key, same as the kunji-native /issue. No new crypto. See docs/oid4vc.md.
import { randomBytes } from 'node:crypto';
import { issue, issueBatch, issuerOrigin, MAX_BATCH } from './issuer.js';
import { verifyProofJwt, verifyDpopProof, verifyPkce, SD_JWT_VC_FORMAT, SD_JWT_VC_FORMATS } from './oid4vc.js';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const AUTH_CODE_GRANT = 'authorization_code';
const CONFIG_ID = 'age'; // the one credential configuration this demo issues
const token = () => randomBytes(24).toString('base64url');

// In-memory stores (a real issuer uses its own DB). Pre-auth codes and access tokens are single-use-ish.
const offers = new Map(); // preAuthorizedCode → { configurationId }
const tokens = new Map(); // access_token → { cNonce, configurationId, jkt? }
const dpopJtis = new Set(); // DPoP proof jti replay cache (RFC 9449) — the server's job, not the lib's
const authSessions = new Map(); // issuer_state → { configurationId } (authorization_code grant)
const authCodes = new Map(); // code → { configurationId, codeChallenge, redirectUri } — single-use

export const credentialIssuerMetadata = () => ({
  credential_issuer: issuerOrigin(),
  credential_endpoint: `${issuerOrigin()}/credential`,
  authorization_servers: [issuerOrigin()],
  credential_configurations_supported: {
    [CONFIG_ID]: {
      format: SD_JWT_VC_FORMAT,
      vct: 'age',
      cryptographic_binding_methods_supported: ['jwk'],
      credential_signing_alg_values_supported: ['EdDSA'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA'] } },
    },
  },
});

export const authServerMetadata = () => ({
  issuer: issuerOrigin(),
  authorization_endpoint: `${issuerOrigin()}/authorize`,
  token_endpoint: `${issuerOrigin()}/token`,
  grant_types_supported: [AUTH_CODE_GRANT, PRE_AUTH_GRANT],
  code_challenge_methods_supported: ['S256'],
  'pre-authorized_grant_anonymous_access_supported': true,
});

/**
 * Mint a credential offer. Default = pre-authorized_code (inline, no tx_code). With `{ authCode:true }`
 * the offer carries the authorization_code grant + an `issuer_state` (the holder then drives /authorize).
 */
export const createOffer = ({ authCode = false } = {}) => {
  const grants = {};
  if (authCode) {
    const issuerState = token();
    authSessions.set(issuerState, { configurationId: CONFIG_ID });
    grants[AUTH_CODE_GRANT] = { issuer_state: issuerState };
  } else {
    const preAuthorizedCode = token();
    offers.set(preAuthorizedCode, { configurationId: CONFIG_ID });
    grants[PRE_AUTH_GRANT] = { 'pre-authorized_code': preAuthorizedCode };
  }
  const offer = {
    credential_issuer: issuerOrigin(),
    credential_configuration_ids: [CONFIG_ID],
    grants,
  };
  const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
  return { offer, offerUri };
};

/**
 * Authorization endpoint (authorization_code grant). A conformance fixture — there is NO real user
 * authn here; it mints a single-use `code`, stores the PKCE `code_challenge` (never the verifier), and
 * returns a 302 to `redirect_uri?code=&state=`. The `issuer_state` (if present) selects the configuration.
 */
export const handleAuthorize = (query = {}) => {
  if (query.response_type !== 'code') return { status: 400, json: { error: 'unsupported_response_type' } };
  if (query.code_challenge_method !== 'S256' || !query.code_challenge) return { status: 400, json: { error: 'invalid_request', detail: 'pkce_s256_required' } };
  const redirectUri = query.redirect_uri;
  if (!redirectUri) return { status: 400, json: { error: 'invalid_request', detail: 'redirect_uri_required' } };
  const session = query.issuer_state && authSessions.get(query.issuer_state);
  const configurationId = (session && session.configurationId) || CONFIG_ID;
  if (query.issuer_state) authSessions.delete(query.issuer_state); // single-use
  const code = token();
  authCodes.set(code, { configurationId, codeChallenge: query.code_challenge, redirectUri });
  const sep = redirectUri.includes('?') ? '&' : '?';
  const location = `${redirectUri}${sep}code=${encodeURIComponent(code)}${query.state ? `&state=${encodeURIComponent(query.state)}` : ''}`;
  return { status: 302, location };
};

/** Token endpoint: redeem a pre-authorized_code OR an authorization_code (+ PKCE) for an access_token. */
export const handleToken = async (body, { dpop, htu } = {}) => {
  let configurationId;
  if (body?.grant_type === PRE_AUTH_GRANT) {
    const code = body['pre-authorized_code'];
    const offer = code && offers.get(code);
    if (!offer) return { status: 400, json: { error: 'invalid_grant' } };
    offers.delete(code); // single-use
    configurationId = offer.configurationId;
  } else if (body?.grant_type === AUTH_CODE_GRANT) {
    // authorization_code grant: look up the code, re-check redirect_uri, and verify the PKCE verifier
    // against the challenge stored at /authorize (S256). Single-use.
    const rec = body.code && authCodes.get(body.code);
    if (!rec) return { status: 400, json: { error: 'invalid_grant' } };
    if (body.redirect_uri !== rec.redirectUri) return { status: 400, json: { error: 'invalid_grant', detail: 'redirect_uri_mismatch' } };
    if (!(await verifyPkce({ codeVerifier: body.code_verifier, codeChallenge: rec.codeChallenge })))
      return { status: 400, json: { error: 'invalid_grant', detail: 'pkce_mismatch' } };
    authCodes.delete(body.code); // single-use
    configurationId = rec.configurationId;
  } else {
    return { status: 400, json: { error: 'unsupported_grant_type' } };
  }
  // DPoP (RFC 9449), opt-in: if the client presents a proof, bind the token to its key (cnf.jkt) and
  // return token_type:'DPoP'. No DPoP header ⇒ today's bearer token, byte-unchanged.
  let jkt;
  if (dpop) {
    const v = await verifyDpopProof({ dpop, htu, htm: 'POST' });
    if (!v.ok) return { status: 400, json: { error: 'invalid_dpop', detail: v.error } };
    if (dpopJtis.has(v.jti)) return { status: 400, json: { error: 'invalid_dpop', detail: 'dpop_replay' } };
    dpopJtis.add(v.jti);
    jkt = v.jkt;
  }
  const access_token = token();
  const cNonce = token();
  tokens.set(access_token, { cNonce, configurationId, jkt });
  return {
    status: 200,
    json: {
      access_token,
      token_type: jkt ? 'DPoP' : 'bearer',
      expires_in: 300,
      c_nonce: cNonce,
      c_nonce_expires_in: 300,
    },
  };
};

/**
 * Credential endpoint: verify the bearer access_token + the holder proof JWT (nonce must equal the
 * token's c_nonce), then mint via the existing issuer. Returns the SD-JWT VC.
 */
export const handleCredential = async ({ authorization, dpop, htu, body }) => {
  // Accept either the DPoP or the Bearer auth scheme (RFC 9449 §7.1) so a legacy bearer client still works.
  const tok = /^(?:DPoP|Bearer) (.+)$/.exec(String(authorization || ''))?.[1];
  const t = tok && tokens.get(tok);
  if (!t) return { status: 401, json: { error: 'invalid_token' } };
  // If the token was DPoP-bound at /token, require a matching DPoP proof here (jkt == bound, ath == token,
  // fresh, non-replayed). A bearer (unbound) token skips DPoP entirely — today's path.
  if (t.jkt) {
    if (!dpop) return { status: 401, json: { error: 'use_dpop_nonce', detail: 'dpop_required' } };
    const v = await verifyDpopProof({ dpop, htu, htm: 'POST', accessToken: tok });
    if (!v.ok) return { status: 400, json: { error: 'invalid_dpop', detail: v.error } };
    if (v.jkt !== t.jkt) return { status: 400, json: { error: 'invalid_dpop', detail: 'dpop_jkt_mismatch' } };
    if (dpopJtis.has(v.jti)) return { status: 400, json: { error: 'invalid_dpop', detail: 'dpop_replay' } };
    dpopJtis.add(v.jti);
  }
  const fmt = body?.format || (body?.credential_configuration_id ? SD_JWT_VC_FORMAT : undefined);
  if (fmt && !SD_JWT_VC_FORMATS.includes(fmt)) return { status: 400, json: { error: 'unsupported_credential_format' } };
  // The SD-JWT VC format id == the minted `typ`; emit whichever name the wallet asked for (default legacy). [dc+sd-jwt]
  const typ = fmt && SD_JWT_VC_FORMATS.includes(fmt) ? fmt : undefined;

  // Batch issuance (unlinkability v2): `proofs.jwt:[…]` — each proof is over a distinct holder key
  // (same c_nonce). Verify all before issuing, then mint one one-time copy per key. [OpenID4VCI batch]
  const batch = body?.proofs?.jwt;
  if (Array.isArray(batch) && batch.length) {
    if (batch.length > MAX_BATCH) return { status: 400, json: { error: 'batch_too_large', max: MAX_BATCH } }; // [S24]
    const holderJwks = [];
    for (const jwt of batch) {
      const v = verifyProofJwt({ proofJwt: jwt, audience: issuerOrigin(), cNonce: t.cNonce });
      if (!v.ok) return { status: 400, json: { error: 'invalid_proof', detail: v.error } };
      holderJwks.push(v.holderJwk);
    }
    tokens.delete(tok); // single-use
    return { status: 200, json: { credentials: issueBatch({ holderJwks, typ }).map((m) => m.credential) } };
  }

  const proofJwt = body?.proof?.jwt;
  if (body?.proof?.proof_type !== 'jwt' || !proofJwt) return { status: 400, json: { error: 'invalid_proof' } };
  const v = verifyProofJwt({ proofJwt, audience: issuerOrigin(), cNonce: t.cNonce });
  if (!v.ok) return { status: 400, json: { error: 'invalid_proof', detail: v.error } };
  tokens.delete(tok); // single-use
  const { credential } = issue({ holderJwk: v.holderJwk, typ });
  return { status: 200, json: { credential } };
};
