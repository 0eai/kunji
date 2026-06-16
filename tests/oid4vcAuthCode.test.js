import { describe, it, expect } from 'vitest';
import { offerNeedsSignIn, completeAuthCodeFlow } from '../src/services/credentials.js';

const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const offer = (grants) =>
  JSON.stringify({
    credential_issuer: 'https://issuer.example.com',
    credential_configuration_ids: ['age_credential'],
    grants,
  });

describe('offerNeedsSignIn — authorization_code vs pre-authorized offers', () => {
  it('true for an authorization_code offer', () => {
    expect(offerNeedsSignIn(offer({ authorization_code: { issuer_state: 'abc' } }))).toBe(true);
  });
  it('false for a pre-authorized offer', () => {
    expect(offerNeedsSignIn(offer({ [PRE_AUTH]: { 'pre-authorized_code': 'xyz' } }))).toBe(false);
  });
  it('false when both grants are present (pre-auth wins — redeemable in place)', () => {
    expect(
      offerNeedsSignIn(
        offer({ authorization_code: { issuer_state: 'a' }, [PRE_AUTH]: { 'pre-authorized_code': 'p' } }),
      ),
    ).toBe(false);
  });
  it('false on a malformed offer', () => {
    expect(offerNeedsSignIn('not an offer')).toBe(false);
    expect(offerNeedsSignIn('{bad json')).toBe(false);
  });
});

describe('completeAuthCodeFlow — CSRF: an unknown/expired state is refused', () => {
  it('rejects when no saved context matches the returned state', async () => {
    // No flow was started (and there is no sessionStorage in the node test env), so the state is
    // unknown → the redeem must NOT proceed. Guards against a forged/replayed ?code=&state= redirect.
    await expect(completeAuthCodeFlow(null, 'some-code', 'unknown-state')).rejects.toThrow(
      /unknown or expired/i,
    );
  });
});
