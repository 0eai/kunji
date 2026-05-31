import { describe, it, expect } from 'vitest';
// Cross-check: the wallet's Ed25519 signer must produce assertions the RP verifier
// accepts (identical canonical-JSON), and each §6 check must reject its bad case.
import {
  verifyAssertion,
  subFromPublicKey,
} from '../examples/kunji-login-demo/functions/verify.js';
import {
  generateMasterKey,
  deriveAppKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../src/lib/crypto/index.js';

const AUD = 'app.com';

async function buildAssertion({
  challenge = 'chal',
  sessionId = 'sess',
  sub,
  timestamp = Date.now(),
  tamper = false,
  claims,
} = {}) {
  const { secretKey, publicKey } = await deriveAppKeyPair(await generateMasterKey(), AUD);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const signedPayload = {
    sessionId,
    challenge,
    audience: AUD,
    sub: sub ?? subFromPublicKey(publicKeyB64),
    timestamp,
  };
  if (claims) signedPayload.claims = claims; // optional self-asserted profile
  // tamper = a valid signature over a *different* payload → fails verification against signedPayload.
  const signedToken = tamper
    ? signWithEd25519({ ...signedPayload, sessionId: sessionId + '_x' }, secretKey)
    : signWithEd25519(signedPayload, secretKey);
  return { publicKey: publicKeyB64, signedPayload, signedToken };
}

const session = (over = {}) => ({
  status: 'pending',
  challenge: 'chal',
  audience: AUD,
  expiresAt: Date.now() + 60_000,
  ...over,
});
const expectErr = (r, error) => {
  expect(r.ok).toBe(false);
  expect(r.error).toBe(error);
};

describe('verifyAssertion', () => {
  it('accepts a correctly signed assertion', async () => {
    const assertion = await buildAssertion();
    const r = verifyAssertion({ assertion, session: session(), audience: AUD });
    expect(r.ok).toBe(true);
    expect(r.sub).toBe(assertion.signedPayload.sub);
    expect(r.claims).toBeNull(); // no profile shared
  });

  it('returns consented profile claims when present', async () => {
    const claims = { name: 'Ada Lovelace', picture: 'data:image/svg+xml,<svg/>' };
    const r = verifyAssertion({
      assertion: await buildAssertion({ claims }),
      session: session(),
      audience: AUD,
    });
    expect(r.ok).toBe(true);
    expect(r.claims).toEqual(claims);
  });

  it('rejects an assertion whose claims were tampered after signing', async () => {
    const assertion = await buildAssertion({ claims: { name: 'Ada' } });
    assertion.signedPayload.claims.name = 'Mallory'; // mutate after signing
    expectErr(verifyAssertion({ assertion, session: session(), audience: AUD }), 'bad_signature');
  });

  it('rejects malformed', () => {
    expectErr(
      verifyAssertion({ assertion: {}, session: session(), audience: AUD }),
      'malformed_assertion',
    );
  });

  it('rejects an unknown session', async () => {
    expectErr(
      verifyAssertion({ assertion: await buildAssertion(), session: null, audience: AUD }),
      'unknown_session',
    );
  });

  it('rejects an already-consumed session', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion(),
        session: session({ status: 'approved' }),
        audience: AUD,
      }),
      'session_consumed',
    );
  });

  it('rejects an expired session', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion(),
        session: session({ expiresAt: Date.now() - 1 }),
        audience: AUD,
      }),
      'session_expired',
    );
  });

  it('rejects a challenge mismatch (replay)', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion(),
        session: session({ challenge: 'other' }),
        audience: AUD,
      }),
      'challenge_mismatch',
    );
  });

  it('rejects an audience mismatch (relay/phishing)', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion(),
        session: session(),
        audience: 'evil.com',
      }),
      'audience_mismatch',
    );
  });

  it('rejects a bad signature', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion({ tamper: true }),
        session: session(),
        audience: AUD,
      }),
      'bad_signature',
    );
  });

  it('rejects a sub that is not SHA-256(publicKey)', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion({ sub: '0'.repeat(64) }),
        session: session(),
        audience: AUD,
      }),
      'sub_mismatch',
    );
  });

  it('rejects a stale timestamp', async () => {
    expectErr(
      verifyAssertion({
        assertion: await buildAssertion({ timestamp: Date.now() - 200_000 }),
        session: session(),
        audience: AUD,
      }),
      'stale_timestamp',
    );
  });
});
