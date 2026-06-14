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
import { issue, issuerOrigin } from './issuer.js';
import { verifyProofJwt, SD_JWT_VC_FORMAT } from './oid4vc.js';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const CONFIG_ID = 'age'; // the one credential configuration this demo issues
const token = () => randomBytes(24).toString('base64url');

// In-memory stores (a real issuer uses its own DB). Pre-auth codes and access tokens are single-use-ish.
const offers = new Map(); // preAuthorizedCode → { configurationId }
const tokens = new Map(); // access_token → { cNonce, configurationId }

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
  token_endpoint: `${issuerOrigin()}/token`,
  'pre-authorized_grant_anonymous_access_supported': true,
});

/** Mint a credential offer (pre-authorized_code grant). The demo embeds the offer inline (no tx_code). */
export const createOffer = () => {
  const preAuthorizedCode = token();
  offers.set(preAuthorizedCode, { configurationId: CONFIG_ID });
  const offer = {
    credential_issuer: issuerOrigin(),
    credential_configuration_ids: [CONFIG_ID],
    grants: { [PRE_AUTH_GRANT]: { 'pre-authorized_code': preAuthorizedCode } },
  };
  const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
  return { offer, offerUri };
};

/** Token endpoint: redeem a pre-authorized_code for an access_token + c_nonce. */
export const handleToken = (body) => {
  if (body?.grant_type !== PRE_AUTH_GRANT) return { status: 400, json: { error: 'unsupported_grant_type' } };
  const code = body['pre-authorized_code'];
  const offer = code && offers.get(code);
  if (!offer) return { status: 400, json: { error: 'invalid_grant' } };
  offers.delete(code); // single-use
  const access_token = token();
  const cNonce = token();
  tokens.set(access_token, { cNonce, configurationId: offer.configurationId });
  return {
    status: 200,
    json: { access_token, token_type: 'bearer', expires_in: 300, c_nonce: cNonce, c_nonce_expires_in: 300 },
  };
};

/**
 * Credential endpoint: verify the bearer access_token + the holder proof JWT (nonce must equal the
 * token's c_nonce), then mint via the existing issuer. Returns the SD-JWT VC.
 */
export const handleCredential = ({ authorization, body }) => {
  const bearer = /^Bearer (.+)$/.exec(String(authorization || ''))?.[1];
  const t = bearer && tokens.get(bearer);
  if (!t) return { status: 401, json: { error: 'invalid_token' } };
  const fmt = body?.format || (body?.credential_configuration_id ? SD_JWT_VC_FORMAT : undefined);
  if (fmt && fmt !== SD_JWT_VC_FORMAT) return { status: 400, json: { error: 'unsupported_credential_format' } };
  const proofJwt = body?.proof?.jwt;
  if (body?.proof?.proof_type !== 'jwt' || !proofJwt) return { status: 400, json: { error: 'invalid_proof' } };
  const v = verifyProofJwt({ proofJwt, audience: issuerOrigin(), cNonce: t.cNonce });
  if (!v.ok) return { status: 400, json: { error: 'invalid_proof', detail: v.error } };
  tokens.delete(bearer); // single-use
  const { credential } = issue({ holderJwk: v.holderJwk });
  return { status: 200, json: { credential } };
};
