// OpenID4VC interop sim — a headless holder that proves both standard halves end-to-end, with the
// SAME SD-JWT VC kunji mints/verifies natively. No human, no kunji server in the path.
//
//   OpenID4VCI (issuance): credential offer → token (pre-authorized_code) → credential request with a
//                          holder proof JWT → an SD-JWT VC.
//   OpenID4VP (presentation): authorization request (presentation_definition) → vp_token → direct_post
//                          → the verifier approves with the verified claim.
//
// Run both demos first, then this:
//     (cd ../kunji-issuer-demo && PORT=4000 node server.js)   # the issuer
//     node server.js                                          # this RP/verifier (port 3000)
//     node oid4vc-sim.js                                      # the holder
// Override hosts: ISSUER=http://… BASE=http://… node oid4vc-sim.js   ·   add --revoke to test rejection.
import { ed25519 } from '@noble/curves/ed25519.js';
import { parseSdJwt } from './vc.js';
import {
  parseCredentialOffer,
  buildProofJwt,
  parseAuthorizationRequest,
  pdToVcQuery,
  buildVpToken,
  buildPresentationSubmission,
} from './oid4vc.js';

const ISSUER = (process.env.ISSUER || 'http://localhost:4000').replace(/\/$/, '');
const BASE = (process.env.BASE || 'http://localhost:3000').replace(/\/$/, '');
const wantRevoke = process.argv.includes('--revoke');
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const getJson = async (u, init) => {
  const r = await fetch(u, init);
  const body = await r.json().catch(() => ({}));
  return { status: r.status, body };
};

// One holder key for the whole flow: it binds the credential (cnf.jwk = proof.jwk at issuance) and
// signs the KB-JWT at presentation. The real wallet uses deriveCredentialHolderKey(masterKey, iss).
const holderSecretKey = ed25519.utils.randomSecretKey();
const holderPublicKey = ed25519.getPublicKey(holderSecretKey);

const fail = (msg, detail) => {
  console.error(`\n✗ ${msg}`, detail ?? '');
  process.exit(1);
};

console.log('OpenID4VC interop sim — issuer:', ISSUER, '· verifier:', BASE, '\n');

// ── 1. OpenID4VCI: offer → token → credential ────────────────────────────────
console.log('① OpenID4VCI issuance');
const offerResp = await getJson(`${ISSUER}/credential-offer`);
if (offerResp.status !== 200) fail('credential-offer failed', offerResp);
const offer = parseCredentialOffer(offerResp.body.offer || offerResp.body.offerUri);
console.log('  • offer            credential_issuer =', offer.credentialIssuer, '· config =', offer.configurationIds.join(','));

const tokenResp = await getJson(`${ISSUER}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.preAuthorizedCode }),
});
if (tokenResp.status !== 200) fail('token request failed', tokenResp);
const { access_token, c_nonce } = tokenResp.body;
console.log('  • token            access_token + c_nonce received');

const proofJwt = buildProofJwt({ holderSecretKey, holderPublicKey, audience: offer.credentialIssuer, cNonce: c_nonce });
const credResp = await getJson(`${ISSUER}/credential`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access_token}` },
  body: JSON.stringify({ format: 'vc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
});
if (credResp.status !== 200 || !credResp.body.credential) fail('credential request failed', credResp);
const sdjwt = credResp.body.credential;
const parsed = parseSdJwt(sdjwt);
console.log('  ✓ credential       vct =', parsed.issuerClaims.vct, '· iss =', parsed.issuerClaims.iss);
console.log('                     claims held:', parsed.disclosures.map((d) => d.name).join(', '));

if (wantRevoke) {
  const idx = parsed.issuerClaims.status?.idx;
  await fetch(`${ISSUER}/status/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idx }),
  });
  console.log('  ! revoked          status idx', idx, '(expecting the presentation to be rejected)');
}

// ── 2. OpenID4VP: request → vp_token → direct_post → result ──────────────────
console.log('\n② OpenID4VP presentation');
const reqResp = await getJson(`${BASE}/oid4vp/request`);
if (reqResp.status !== 200) fail('oid4vp/request failed', reqResp);
const ar = parseAuthorizationRequest(reqResp.body.requestUri);
const q = pdToVcQuery(ar.presentationDefinition);
console.log('  • request          client_id =', ar.clientId, '· asks vct =', q.vct, '· disclose =', q.disclose.join(','));

const vpToken = await buildVpToken({
  sdjwt,
  disclose: q.disclose,
  clientId: ar.clientId,
  nonce: ar.nonce,
  holderSecretKey,
});
const presentationSubmission = buildPresentationSubmission(ar.presentationDefinition);
const respResp = await getJson(ar.responseUri, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ vp_token: vpToken, presentation_submission: presentationSubmission, state: reqResp.body.state }),
});

if (wantRevoke) {
  if (respResp.status === 400 && /revoked/.test(respResp.body.error || '')) {
    console.log('  ✓ rejected         verifier refused the revoked credential →', respResp.body.error);
    process.exit(0);
  }
  fail('expected the revoked credential to be rejected, but it was accepted', respResp);
}

if (respResp.status !== 200 || respResp.body.status !== 'approved') fail('direct_post rejected', respResp);
console.log('  ✓ approved         verifier accepted · verified claims =', JSON.stringify(respResp.body.claims));
console.log('\n✓ End-to-end: a credential ISSUED over OpenID4VCI, PRESENTED over OpenID4VP — same SD-JWT VC bytes.');
process.exit(0);
