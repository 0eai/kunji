import { describe, it, expect } from 'vitest';
// The OpenID4VCI authorization_code grant + PKCE (S256). The wallet UI is deferred (kunji is QR/no-redirect),
// but the lib helpers + offer parsing are exercised here; the issuer demo + the headless sim (`oid4vc-sim
// --auth-code`) prove the authorize→token→credential round-trip.
import {
  generateCodeVerifier,
  computeCodeChallenge,
  generatePkce,
  verifyPkce,
  parseCredentialOffer,
  buildAuthorizationRequest,
} from '../src/lib/oid4vc.js';
import { createOffer, handleAuthorize, handleToken } from '../examples/kunji-issuer-demo/oid4vci.js';

const ISS = 'https://issuer.example';

describe('PKCE (RFC 7636, S256)', () => {
  it('matches the RFC 7636 Appendix B test vector', async () => {
    // The canonical example verifier → challenge from the spec.
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await computeCodeChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('generatePkce → verifyPkce round-trips; a wrong verifier fails', async () => {
    const { codeVerifier, codeChallenge, codeChallengeMethod } = await generatePkce();
    expect(codeChallengeMethod).toBe('S256');
    expect(await verifyPkce({ codeVerifier, codeChallenge })).toBe(true);
    expect(await verifyPkce({ codeVerifier: 'wrong-verifier', codeChallenge })).toBe(false);
  });

  it('a code_verifier is 43 chars of the base64url charset', () => {
    const v = generateCodeVerifier();
    expect(v).toHaveLength(43); // 32 bytes → 43 unpadded base64url chars
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('authorization_code offer + request', () => {
  it('parseCredentialOffer surfaces the authorization_code grant (and pre-auth offers stay unchanged)', () => {
    const authOffer = {
      credential_issuer: ISS,
      credential_configuration_ids: ['age'],
      grants: { authorization_code: { issuer_state: 'st-1' } },
    };
    const parsed = parseCredentialOffer(authOffer);
    expect(parsed.authorizationCode).toEqual({ issuerState: 'st-1', authorizationServer: undefined });
    expect(parsed.preAuthorizedCode).toBeUndefined();
    // a pre-authorized offer carries no authorizationCode (back-compat)
    const preAuth = parseCredentialOffer({
      credential_issuer: ISS,
      credential_configuration_ids: ['age'],
      grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'abc' } },
    });
    expect(preAuth.preAuthorizedCode).toBe('abc');
    expect(preAuth.authorizationCode).toBeUndefined();
  });

  it('buildAuthorizationRequest produces a code+S256 request with authorization_details + state', () => {
    const { url, params } = buildAuthorizationRequest({
      authorizationEndpoint: `${ISS}/authorize`,
      clientId: 'https://wallet.example/cb',
      redirectUri: 'https://wallet.example/cb',
      codeChallenge: 'cc',
      state: 'st',
      issuerState: 'is',
      credentialIssuer: ISS,
      configurationId: 'age',
    });
    expect(url.startsWith(`${ISS}/authorize?`)).toBe(true);
    expect(params.get('response_type')).toBe('code');
    expect(params.get('code_challenge_method')).toBe('S256');
    expect(params.get('code_challenge')).toBe('cc');
    expect(params.get('state')).toBe('st');
    expect(params.get('issuer_state')).toBe('is');
    const ad = JSON.parse(params.get('authorization_details'));
    expect(ad[0]).toMatchObject({ type: 'openid_credential', credential_configuration_id: 'age', locations: [ISS] });
  });
});

// Issuer-side enforcement (these all reject at /token, before any credential mint — no key side effects).
describe('authorization_code at the issuer demo (PKCE + single-use enforcement)', () => {
  const REDIRECT = 'https://wallet.example/cb';
  const drive = async () => {
    const issuerState = createOffer({ authCode: true }).offer.grants.authorization_code.issuer_state;
    const pkce = await generatePkce();
    const auth = handleAuthorize({
      response_type: 'code',
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
      redirect_uri: REDIRECT,
      issuer_state: issuerState,
      state: 'st',
    });
    expect(auth.status).toBe(302);
    return { code: new URL(auth.location).searchParams.get('code'), pkce };
  };

  it('authorize → token (correct verifier) issues an access_token', async () => {
    const { code, pkce } = await drive();
    const r = await handleToken({ grant_type: 'authorization_code', code, code_verifier: pkce.codeVerifier, redirect_uri: REDIRECT });
    expect(r.status).toBe(200);
    expect(r.json.access_token).toBeTruthy();
  });

  it('rejects a wrong code_verifier (pkce_mismatch)', async () => {
    const { code } = await drive();
    const r = await handleToken({ grant_type: 'authorization_code', code, code_verifier: 'wrong', redirect_uri: REDIRECT });
    expect(r.json).toMatchObject({ error: 'invalid_grant', detail: 'pkce_mismatch' });
  });

  it('rejects a redirect_uri mismatch', async () => {
    const { code, pkce } = await drive();
    const r = await handleToken({ grant_type: 'authorization_code', code, code_verifier: pkce.codeVerifier, redirect_uri: 'https://evil.example/cb' });
    expect(r.json).toMatchObject({ error: 'invalid_grant', detail: 'redirect_uri_mismatch' });
  });

  it('rejects a replayed code (single-use)', async () => {
    const { code, pkce } = await drive();
    expect((await handleToken({ grant_type: 'authorization_code', code, code_verifier: pkce.codeVerifier, redirect_uri: REDIRECT })).status).toBe(200);
    const replay = await handleToken({ grant_type: 'authorization_code', code, code_verifier: pkce.codeVerifier, redirect_uri: REDIRECT });
    expect(replay.json.error).toBe('invalid_grant');
  });
});
