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
    expect(pdToVcQuery(pd)).toEqual({ vct: 'age', iss: undefined, disclose: ['age_over_18'] });
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
    expect(pdToVcQuery(ar.presentationDefinition)).toEqual({ vct: 'age', iss: undefined, disclose: ['age_over_18'] });
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
