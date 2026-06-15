// The VERIFIER half of the kunji-demo live credentials demo — a Firebase-adapted port of the
// /oid4vp/* logic in examples/kunji-node-demo/server.js. No filesystem / module state: the Ed25519
// request-signing key comes from a Secret (passed in) and the request sessions live in Firestore
// (see index.js). Scope: a signed inline JAR + DCQL + cleartext direct_post (the demo's first cut).
import { ed25519 } from '@noble/curves/ed25519.js';
import { buildSignedAuthorizationRequest, buildDcqlQuery, verifyVpToken } from './oid4vc.js';

export const VERIFIER_KID = 'verifier-key-1';
export const VP_QUERY = { vct: 'age', disclose: ['age_over_18'] };
const b64u = (b) => Buffer.from(b).toString('base64url');

/** Load the verifier Ed25519 keypair from a base64 secret-key string (the VERIFIER_SIGNING_KEY secret). */
export const verifierKey = (secretKeyB64) => {
  const secretKey = new Uint8Array(Buffer.from(String(secretKeyB64).trim(), 'base64'));
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
};

/** The verifier's published request-signing key (HTTPS-anchored client_id scheme). */
export const verifierWellKnown = (clientId, publicKey) => ({
  client_id: clientId,
  name: 'kunji demo verifier',
  keys: [{ kid: VERIFIER_KID, kty: 'OKP', crv: 'Ed25519', x: b64u(publicKey) }],
});

/**
 * Build a signed OpenID4VP request (inline JAR) asking for `age_over_18` over DCQL, with a cleartext
 * direct_post response. Returns the `openid4vp://` URI + the `dcqlQuery`/`nonce` to persist for verify.
 */
export const buildVpRequest = ({ secretKey, clientId, base, state, nonce }) => {
  const dcqlQuery = buildDcqlQuery({ id: 'age_cred', ...VP_QUERY });
  const params = {
    response_type: 'vp_token',
    client_id: clientId,
    response_mode: 'direct_post',
    response_uri: `${base}/oid4vp/response`,
    nonce,
    state,
    dcql_query: dcqlQuery,
  };
  const requestJwt = buildSignedAuthorizationRequest(secretKey, { kid: VERIFIER_KID, params });
  const requestUri = `openid4vp://?${new URLSearchParams({ client_id: clientId, request: requestJwt }).toString()}`;
  return { requestUri, dcqlQuery };
};

/**
 * Verify a posted vp_token against the (locally-resolved) issuer keys + StatusList. `getIssuerKeys` and
 * `checkStatus` are injected by index.js (resolved locally — the credential's `iss` is this same demo).
 * @returns {Promise<{ ok:true, vct, iss, claims } | { ok:false, error }>}
 */
export const verifyVp = ({ vpToken, dcqlQuery, clientId, nonce, getIssuerKeys, checkStatus }) =>
  verifyVpToken({ vpToken, dcqlQuery, getIssuerKeys, checkStatus, clientId, nonce });
