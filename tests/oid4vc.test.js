import { describe, it, expect } from 'vitest';
import {
  parseCredentialOffer,
  buildProofJwt,
  verifyProofJwt,
  buildPresentationDefinition,
  parseAuthorizationRequest,
  pdToVcQuery,
  buildVpToken,
  buildPresentationSubmission,
  verifyVpToken,
  buildSignedAuthorizationRequest,
  verifyRequestObject,
  buildDcqlQuery,
  dcqlToVcQuery,
  requestQuery,
  buildVpResponse,
} from '../src/lib/oid4vc.js';
import { mintCredential, holderJwkFor, matchCredentialsByScope } from '../src/lib/vc.js';
import { generateEd25519KeyPair, exportEd25519PublicKey } from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';

// OpenID4VC interop is a thin envelope over the SD-JWT VC core: the OID4VCI proof JWT and the OID4VP
// vp_token (KB-JWT) both bind the same holder key, and verifyVpToken wraps the unchanged
// verifyCredentialPresentation + the presentation_definition constraints. These exercise that envelope.

const ISS = 'https://issuer.example';
const KID = 'issuer-key-1';
const CLIENT = 'verifier.example';
const NONCE = 'n'.repeat(24);
const issuerKeysFor = (pub) => async () => [{ ...okpJwk(pub), kid: KID }];

// Mint an SD-JWT VC bound to a fresh holder key; return what the VP/VCI tests need.
const setup = async ({ claims = { age_over_18: true, age_over_21: false }, vct = 'age' } = {}) => {
  const issuer = generateEd25519KeyPair();
  const holder = generateEd25519KeyPair();
  const sdjwt = await mintCredential(issuer.secretKey, {
    kid: KID,
    iss: ISS,
    vct,
    claims,
    holderJwk: holderJwkFor(holder.publicKey),
    ttlSeconds: 3600,
  });
  return { issuer, holder, sdjwt, getIssuerKeys: issuerKeysFor(issuer.publicKey) };
};

describe('OpenID4VCI envelope', () => {
  it('parseCredentialOffer round-trips an offer URI (pre-authorized_code)', () => {
    const offer = {
      credential_issuer: ISS,
      credential_configuration_ids: ['age'],
      grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'abc123' } },
    };
    const uri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
    expect(parseCredentialOffer(uri)).toEqual({
      credentialIssuer: ISS,
      configurationIds: ['age'],
      preAuthorizedCode: 'abc123',
      txCode: undefined,
    });
    // and from the offer object directly
    expect(parseCredentialOffer(offer).preAuthorizedCode).toBe('abc123');
  });

  it('buildProofJwt → verifyProofJwt binds the holder jwk; wrong aud/nonce fail', () => {
    const holder = generateEd25519KeyPair();
    const proofJwt = buildProofJwt({
      holderSecretKey: holder.secretKey,
      holderPublicKey: holder.publicKey,
      audience: ISS,
      cNonce: 'cn-1',
    });
    const r = verifyProofJwt({ proofJwt, audience: ISS, cNonce: 'cn-1' });
    expect(r.ok).toBe(true);
    expect(r.holderJwk.x).toBe(exportEd25519PublicKey(holder.publicKey).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    expect(verifyProofJwt({ proofJwt, audience: 'https://evil.example', cNonce: 'cn-1' })).toMatchObject({ ok: false, error: 'proof_audience_mismatch' });
    expect(verifyProofJwt({ proofJwt, audience: ISS, cNonce: 'cn-2' })).toMatchObject({ ok: false, error: 'proof_nonce_mismatch' });
  });
});

describe('OpenID4VP presentation_definition ↔ vc query', () => {
  it('maps a presentation_definition to { vct, disclose }', () => {
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    expect(pdToVcQuery(pd)).toEqual({ vct: 'age', iss: undefined, disclose: ['age_over_18'], format: 'vc+sd-jwt' });
  });

  it('builds a presentation_submission referencing the PD', () => {
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const sub = buildPresentationSubmission(pd);
    expect(sub).toMatchObject({ definition_id: 'age', descriptor_map: [{ id: 'age', format: 'vc+sd-jwt', path: '$' }] });
  });

  it('parseAuthorizationRequest surfaces state (echoed back in the direct_post)', () => {
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const params = new URLSearchParams({
      response_type: 'vp_token',
      client_id: CLIENT,
      response_mode: 'direct_post',
      response_uri: 'https://verifier.example/response',
      nonce: NONCE,
      state: 'st-123',
      presentation_definition: JSON.stringify(pd),
    });
    const ar = parseAuthorizationRequest(`openid4vp://?${params.toString()}`);
    expect(ar).toMatchObject({
      responseType: 'vp_token',
      clientId: CLIENT,
      nonce: NONCE,
      state: 'st-123',
      responseUri: 'https://verifier.example/response',
    });
    expect(pdToVcQuery(ar.presentationDefinition)).toEqual({ vct: 'age', iss: undefined, disclose: ['age_over_18'], format: 'vc+sd-jwt' });
  });
});

// The wallet's present path: a verifier's request → a `vc:` query → match a held credential →
// vp_token → verify. Mirrors Dashboard.handlePresentationRequest + presentViaOid4vp end-to-end.
describe('wallet OpenID4VP present path', () => {
  it('matches a held credential to the request and presents → verifies', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup();
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const q = pdToVcQuery(pd);
    const scopeId = 'vc:' + q.vct + (q.disclose.length ? '#' + q.disclose.join(',') : '');
    const matches = matchCredentialsByScope([{ credId: 'c1', vct: 'age', iss: ISS, sdjwt }], [scopeId]);
    expect(matches).toHaveLength(1);
    const { cred, disclose } = matches[0];
    const vpToken = await buildVpToken({ sdjwt: cred.sdjwt, disclose, clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const r = await verifyVpToken({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, vct: 'age', claims: { age_over_18: true } });
  });
});

describe('OpenID4VP vp_token end-to-end (over the SD-JWT VC core)', () => {
  it('present → verify resolves only the requested predicate', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup();
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const vpToken = await buildVpToken({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const r = await verifyVpToken({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, iss: ISS, vct: 'age', claims: { age_over_18: true } });
    expect(r.claims.age_over_21).toBeUndefined(); // not disclosed
  });

  it('rejects a wrong verifier (client_id) or replayed nonce', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup();
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const vpToken = await buildVpToken({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    expect(await verifyVpToken({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: 'evil.example', nonce: NONCE })).toMatchObject({ ok: false, error: 'kb_audience_mismatch' });
    expect(await verifyVpToken({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: 'd'.repeat(24) })).toMatchObject({ ok: false, error: 'kb_nonce_mismatch' });
  });

  it('rejects when the requested predicate is not satisfied (disclosed false)', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup({ claims: { age_over_18: false } });
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const vpToken = await buildVpToken({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    expect(await verifyVpToken({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE })).toMatchObject({ ok: false, error: 'predicate_failed' });
  });

  it('rejects a vct the verifier did not ask for', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup({ vct: 'membership', claims: { age_over_18: true } });
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const vpToken = await buildVpToken({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    expect(await verifyVpToken({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE })).toMatchObject({ ok: false, error: 'vct_mismatch' });
  });
});

// Verifier authentication: a signed authorization request (JAR) verified against the verifier's
// published key (HTTPS-anchored client_id scheme) — proves who's asking.
describe('OpenID4VP signed request objects', () => {
  const VKID = 'v1';
  const VCID = 'https://verifier.example';
  const verifier = generateEd25519KeyPair();
  const verifierKeys = async () => [{ ...okpJwk(verifier.publicKey), kid: VKID }];
  const params = () => ({
    client_id: VCID,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: `${VCID}/response`,
    nonce: NONCE,
    state: 'st',
    dcql_query: buildDcqlQuery({ id: 'c', vct: 'age', disclose: ['age_over_18'] }),
  });

  it('build → parse (signed:true, params from the JWS) → verify against the verifier key', async () => {
    const jwt = buildSignedAuthorizationRequest(verifier.secretKey, { kid: VKID, params: params() });
    const ar = parseAuthorizationRequest(`openid4vp://?client_id=${encodeURIComponent(VCID)}&request=${jwt}`);
    expect(ar).toMatchObject({ signed: true, clientId: VCID, nonce: NONCE, responseUri: `${VCID}/response` });
    expect(ar.dcqlQuery).toBeTruthy();
    expect(await verifyRequestObject({ requestJwt: ar.requestJwt, getVerifierKeys: verifierKeys, clientId: ar.clientId })).toMatchObject({ ok: true, clientId: VCID });
  });

  it('rejects forged signature / wrong key / client_id mismatch / expired', async () => {
    const jwt = buildSignedAuthorizationRequest(verifier.secretKey, { kid: VKID, params: params() });
    const forged = jwt.slice(0, -1) + (jwt.endsWith('A') ? 'B' : 'A');
    expect(await verifyRequestObject({ requestJwt: forged, getVerifierKeys: verifierKeys, clientId: VCID })).toMatchObject({ ok: false, error: 'bad_request_signature' });
    const attacker = generateEd25519KeyPair();
    const wrongKeys = async () => [{ ...okpJwk(attacker.publicKey), kid: VKID }];
    expect(await verifyRequestObject({ requestJwt: jwt, getVerifierKeys: wrongKeys, clientId: VCID })).toMatchObject({ ok: false, error: 'bad_request_signature' });
    expect(await verifyRequestObject({ requestJwt: jwt, getVerifierKeys: verifierKeys, clientId: 'https://evil.example' })).toMatchObject({ ok: false, error: 'client_id_mismatch' });
    const stale = buildSignedAuthorizationRequest(verifier.secretKey, { kid: VKID, params: params(), ttlSeconds: 1, now: Date.now() - 10_000 });
    expect(await verifyRequestObject({ requestJwt: stale, getVerifierKeys: verifierKeys, clientId: VCID })).toMatchObject({ ok: false, error: 'request_expired' });
  });

  it('an unsigned request parses as signed:false', () => {
    const ar = parseAuthorizationRequest(`openid4vp://?client_id=${encodeURIComponent(VCID)}&nonce=${NONCE}&response_uri=${encodeURIComponent(VCID + '/r')}`);
    expect(ar.signed).toBe(false);
  });
});

describe('OpenID4VP DCQL', () => {
  it('buildDcqlQuery → dcqlToVcQuery / requestQuery map to {vct,disclose}', () => {
    const dcql = buildDcqlQuery({ id: 'c', vct: 'age', disclose: ['age_over_18'] });
    expect(dcqlToVcQuery(dcql)).toEqual({ id: 'c', vct: 'age', iss: undefined, disclose: ['age_over_18'], format: 'vc+sd-jwt' });
    expect(requestQuery({ dcqlQuery: dcql })).toMatchObject({ kind: 'dcql', id: 'c', vct: 'age', disclose: ['age_over_18'] });
    expect(requestQuery({ presentationDefinition: buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] }) })).toMatchObject({ kind: 'pd', vct: 'age', disclose: ['age_over_18'] });
  });

  it('DCQL: keyed vp_token (no submission) → verify', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup();
    const dcql = buildDcqlQuery({ id: 'c', vct: 'age', disclose: ['age_over_18'] });
    const request = { dcqlQuery: dcql, clientId: CLIENT, nonce: NONCE, state: 'st' };
    const presentation = await buildVpToken({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const body = buildVpResponse({ request, presentation });
    expect(body.vp_token).toHaveProperty('c');
    expect(body.presentation_submission).toBeUndefined();
    const r = await verifyVpToken({ vpToken: body.vp_token, dcqlQuery: dcql, getIssuerKeys, clientId: CLIENT, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, vct: 'age', claims: { age_over_18: true } });
  });

  it('PD: bare vp_token + a submission → verify (unchanged path)', async () => {
    const { holder, sdjwt, getIssuerKeys } = await setup();
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    const request = { presentationDefinition: pd, clientId: CLIENT, nonce: NONCE, state: 'st' };
    const presentation = await buildVpToken({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const body = buildVpResponse({ request, presentation });
    expect(typeof body.vp_token).toBe('string');
    expect(body.presentation_submission).toBeTruthy();
    const r = await verifyVpToken({ vpToken: body.vp_token, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, claims: { age_over_18: true } });
  });
});
