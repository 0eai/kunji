// OpenID4VC interop sim — a headless holder that proves both standard halves end-to-end, with the
// SAME SD-JWT VC kunji mints/verifies natively. No human, no kunji server in the path.
//
//   OpenID4VCI (issuance): credential offer → token (pre-authorized_code) → credential request with a
//                          holder proof JWT → an SD-JWT VC.
//   OpenID4VP (presentation): a SIGNED authorization request (verified against the verifier's published
//                          key) carrying a DCQL query → vp_token → direct_post → approved. Also checks a
//                          forged request is rejected. `--legacy` exercises the unsigned + presentation_definition path.
//
// Run both demos first, then this:
//     (cd ../kunji-issuer-demo && PORT=4000 node server.js)   # the issuer
//     node server.js                                          # this RP/verifier (port 3000)
//     node oid4vc-sim.js                                      # the holder
// Override hosts: ISSUER=http://… BASE=http://… node oid4vc-sim.js
// Flags: --revoke / --legacy / --ref (request_uri) / --enc (encrypted response) / --dc-sd-jwt (renamed
//        format) / --dpop (sender-constrained access token, RFC 9449) / --auth-code (authorization_code + PKCE)
//        / --scheme=did:jwk (the did client_id scheme).
import { ed25519 } from '@noble/curves/ed25519.js';
import { parseSdJwt } from './vc.js';
import {
  parseCredentialOffer,
  buildProofJwt,
  buildDpopProof,
  generatePkce,
  buildAuthorizationRequest,
  resolveAuthorizationEndpoint,
  resolveAuthorizationRequest,
  verifyRequestObject,
  requestQuery,
  buildVpToken,
  buildVpResponse,
} from './oid4vc.js';
import { encryptJwe } from './jwe.js';
import { resolveDidKey } from './did.js';

const ISSUER = (process.env.ISSUER || 'http://localhost:4000').replace(/\/$/, '');
const BASE = (process.env.BASE || 'http://localhost:3000').replace(/\/$/, '');
const wantRevoke = process.argv.includes('--revoke');
const legacy = process.argv.includes('--legacy'); // unsigned request + presentation_definition
const wantRef = process.argv.includes('--ref'); // request delivered by-reference (request_uri)
const wantEnc = process.argv.includes('--enc'); // encrypted response (direct_post.jwt)
const wantDcSdJwt = process.argv.includes('--dc-sd-jwt'); // request the renamed `dc+sd-jwt` format
const wantDpop = process.argv.includes('--dpop'); // sender-constrained access token (RFC 9449)
const wantAuthCode = process.argv.includes('--auth-code'); // authorization_code grant + PKCE (S256)
const wantScheme = (process.argv.find((a) => a.startsWith('--scheme=')) || '').slice('--scheme='.length); // e.g. did:jwk
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const AUTH_CODE_GRANT = 'authorization_code';

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
const offerResp = await getJson(`${ISSUER}/credential-offer${wantAuthCode ? '?grant=authorization_code' : ''}`);
if (offerResp.status !== 200) fail('credential-offer failed', offerResp);
const offer = parseCredentialOffer(offerResp.body.offer || offerResp.body.offerUri);
console.log('  • offer            credential_issuer =', offer.credentialIssuer, '· config =', offer.configurationIds.join(','));

// DPoP (RFC 9449): a fresh ephemeral key sender-constrains the access token at /token + /credential.
const dpopSk = ed25519.utils.randomSecretKey();
const dpopPk = ed25519.getPublicKey(dpopSk);
const dpopFor = (path, accessToken) =>
  buildDpopProof({ htu: `${ISSUER}${path}`, htm: 'POST', accessToken, holderSecretKey: dpopSk, holderPublicKey: dpopPk });

let access_token, c_nonce, token_type;
if (wantAuthCode) {
  // authorization_code grant + PKCE: resolve the AS, build the authorize request, follow the 302 to read
  // the code (asserting the state echo — CSRF), then redeem code + code_verifier at /token.
  if (!offer.authorizationCode) fail('expected an authorization_code grant in the offer', offer);
  const { authorizationEndpoint, tokenEndpoint } = await resolveAuthorizationEndpoint(offer.credentialIssuer);
  const pkce = await generatePkce();
  const state = globalThis.crypto.randomUUID();
  const redirectUri = `${ISSUER}/callback`;
  const { url } = buildAuthorizationRequest({
    authorizationEndpoint,
    clientId: redirectUri,
    redirectUri,
    codeChallenge: pkce.codeChallenge,
    state,
    issuerState: offer.authorizationCode.issuerState,
    credentialIssuer: offer.credentialIssuer,
    configurationId: offer.configurationIds[0],
  });
  const authResp = await fetch(url, { redirect: 'manual' });
  const loc = authResp.headers.get('location');
  if (!loc) fail('authorize did not redirect (no Location)', { status: authResp.status });
  const back = new URL(loc);
  if (back.searchParams.get('state') !== state) fail('authorize state mismatch (CSRF)');
  const code = back.searchParams.get('code');
  console.log('  • authorize        code received · state verified (PKCE S256)');
  const tr = await getJson(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(wantDpop ? { DPoP: await dpopFor('/token') } : {}) },
    body: JSON.stringify({ grant_type: AUTH_CODE_GRANT, code, code_verifier: pkce.codeVerifier, redirect_uri: redirectUri }),
  });
  if (tr.status !== 200) fail('token (authorization_code) failed', tr);
  ({ access_token, c_nonce, token_type } = tr.body);
} else {
  const tokenResp = await getJson(`${ISSUER}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(wantDpop ? { DPoP: await dpopFor('/token') } : {}) },
    body: JSON.stringify({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.preAuthorizedCode }),
  });
  if (tokenResp.status !== 200) fail('token request failed', tokenResp);
  ({ access_token, c_nonce, token_type } = tokenResp.body);
}
if (wantDpop && token_type !== 'DPoP') fail('expected token_type DPoP', token_type);
console.log('  • token            access_token + c_nonce received', wantDpop ? `· token_type = ${token_type}` : '');

const proofJwt = buildProofJwt({ holderSecretKey, holderPublicKey, audience: offer.credentialIssuer, cNonce: c_nonce });
if (wantDpop) {
  // Negative probe FIRST (the handler rejects before consuming the single-use token): a DPoP proof
  // signed by a DIFFERENT key must be rejected with a jkt mismatch.
  const evilSk = ed25519.utils.randomSecretKey();
  const evilProof = await buildDpopProof({
    htu: `${ISSUER}/credential`,
    htm: 'POST',
    accessToken: access_token,
    holderSecretKey: evilSk,
    holderPublicKey: ed25519.getPublicKey(evilSk),
  });
  const evil = await getJson(`${ISSUER}/credential`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${access_token}`, DPoP: evilProof },
    body: JSON.stringify({ proof: { proof_type: 'jwt', jwt: proofJwt } }),
  });
  if (evil.status === 200) fail('a wrong-key DPoP proof was unexpectedly accepted');
  console.log('  ✓ DPoP forgery     wrong-key proof rejected →', evil.body.detail || evil.body.error);
}
const credResp = await getJson(`${ISSUER}/credential`, {
  method: 'POST',
  headers: wantDpop
    ? { 'Content-Type': 'application/json', Authorization: `DPoP ${access_token}`, DPoP: await dpopFor('/credential', access_token) }
    : { 'Content-Type': 'application/json', Authorization: `Bearer ${access_token}` },
  body: JSON.stringify({ format: wantDcSdJwt ? 'dc+sd-jwt' : 'vc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
});
if (credResp.status !== 200 || !credResp.body.credential) fail('credential request failed', credResp);
if (wantDpop) console.log('  ✓ DPoP             sender-constrained token accepted (jkt-bound)');
const sdjwt = credResp.body.credential;
const parsed = parseSdJwt(sdjwt);
console.log('  ✓ credential       vct =', parsed.issuerClaims.vct, '· iss =', parsed.issuerClaims.iss, '· typ =', parsed.issuerHeader.typ);
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

// ── 2. OpenID4VP: (verify signed request →) present → direct_post → result ───────
const modes = [
  legacy ? 'unsigned + presentation_definition' : 'signed request + DCQL',
  wantRef ? 'request_uri by-reference' : null,
  wantEnc ? 'encrypted response (direct_post.jwt)' : null,
  wantDcSdJwt ? 'dc+sd-jwt format' : null,
  wantScheme ? `client_id scheme ${wantScheme}` : null,
].filter(Boolean);
console.log(`\n② OpenID4VP presentation (${modes.join(' · ')})`);
const params = [
  legacy ? 'signed=0&query=pd' : null,
  wantRef ? 'ref=1' : null,
  wantEnc ? 'enc=1' : null,
  wantDcSdJwt ? 'format=dc-sd-jwt' : null,
  wantScheme ? `scheme=${encodeURIComponent(wantScheme)}` : null,
].filter(Boolean);
const reqUrl = `${BASE}/oid4vp/request${params.length ? `?${params.join('&')}` : ''}`;
const reqResp = await getJson(reqUrl);
if (reqResp.status !== 200) fail('oid4vp/request failed', reqResp);
// resolveAuthorizationRequest fetches the signed request object when the verifier delivered it
// by-reference (request_uri); an inline request is parsed directly. The signature check below is the
// trust anchor either way — an untrusted request_uri host can't forge a verifier.
const ar = await resolveAuthorizationRequest(reqResp.body.requestUri);
if (wantRef) console.log('  ✓ request fetched   resolved request_uri →', ar.signed ? 'signed JAR' : 'inline');

// Verifier authentication: a signed request must verify against the verifier's published key.
const getVerifierKeys = async (clientId) => (await getJson(`${clientId}/.well-known/kunji-verifier.json`)).body.keys || [];
if (ar.signed) {
  const vr = await verifyRequestObject({ requestJwt: ar.requestJwt, getVerifierKeys, resolveDidKey, clientId: ar.clientId });
  if (!vr.ok) fail('signed request did not verify', vr);
  console.log('  ✓ request verified  signed by', ar.clientId.slice(0, 48), `(scheme: ${vr.scheme})`);
  // Forgery check: tamper the JWS signature → must NOT verify. Flip the FIRST char of the signature
  // segment (always data bits); flipping the LAST base64url char can hit padding bits and decode
  // unchanged (a no-op), which would make this probe intermittently pass a forgery.
  const dot = ar.requestJwt.lastIndexOf('.');
  const sig = ar.requestJwt.slice(dot + 1);
  const forged = ar.requestJwt.slice(0, dot + 1) + (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  const fr = await verifyRequestObject({ requestJwt: forged, getVerifierKeys, resolveDidKey, clientId: ar.clientId });
  if (fr.ok) fail('a forged request unexpectedly verified');
  console.log('  ✓ forgery rejected  tampered request →', fr.error);
} else {
  console.log('  • request unsigned  (verifier identity unverified)');
}

const q = requestQuery(ar);
console.log('  • asks             client_id =', ar.clientId, '· vct =', q.vct, '· disclose =', q.disclose.join(','), '· query =', q.kind);
const vpToken = await buildVpToken({ sdjwt, disclose: q.disclose, clientId: ar.clientId, nonce: ar.nonce, holderSecretKey });
const responseBody = buildVpResponse({ request: ar, presentation: vpToken });
let postBody = responseBody;
if (ar.responseMode === 'direct_post.jwt') {
  // Encrypt the vp_token to the verifier's published P-256 enc key (signature-protected in
  // client_metadata) — ECDH-ES + A256GCM JWE. On-path/transport can't read the presentation.
  const encJwk = (ar.clientMetadata?.jwks?.keys || []).find((k) => k.crv === 'P-256');
  if (!encJwk) fail('direct_post.jwt requested but no verifier enc key in client_metadata');
  postBody = { response: await encryptJwe(responseBody, encJwk), state: ar.state };
  console.log('  ✓ response encrypted vp_token JWE-encrypted to verifier enc key (' + encJwk.kid + ')');
}
const respResp = await getJson(ar.responseUri, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(postBody),
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
