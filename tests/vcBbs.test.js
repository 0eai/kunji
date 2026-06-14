import { describe, it, expect } from 'vitest';
import {
  mintBbsCredential,
  buildBbsPresentation,
  verifyBbsPresentation,
  bbsKeyGen,
  bbsClaimNames,
  encodeBbsPresentation,
  decodeBbsPresentation,
  isBbsPresentation,
} from '../src/lib/vcBbs.js';

// BBS credential format (verified-credentials.md §7 v3): ONE credential derives a fresh, randomized
// zero-knowledge proof per presentation — unlinkable across verifiers, no extra copies (v2 needed N).

const ISS = 'https://issuer.example';
const VCT = 'age';

const setup = async (claims = { age_over_18: true, age_over_21: true, name: 'Ada' }, opts = {}) => {
  const { secretKey, publicKey } = await bbsKeyGen();
  const credential = await mintBbsCredential(secretKey, publicKey, { iss: ISS, vct: VCT, claims, ttlSeconds: 365 * 86400, ...opts });
  const getIssuerBbsKey = async () => publicKey;
  return { publicKey, credential, getIssuerBbsKey };
};
const present = (credential, publicKey, disclose, audience, nonce) =>
  buildBbsPresentation({ credential, disclose, audience, nonce, issuerPublicKey: publicKey });

describe('BBS credential — mint / present / verify', () => {
  it('mints with a coarse (day-aligned) exp and sorted claim names', async () => {
    const { credential } = await setup();
    expect(credential.format).toBe('bbs');
    expect(credential.exp % 86400).toBe(0); // coarse — not a per-second handle [§7/S23]
    expect(bbsClaimNames(credential)).toEqual(['age_over_18', 'age_over_21', 'name']);
  });

  it('presents a subset and verifies; undisclosed claims stay hidden', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const p = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'n1');
    const v = await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://a.example', nonce: 'n1' });
    expect(v.ok).toBe(true);
    expect(v.claims).toEqual({ age_over_18: true });
    expect(v.iss).toBe(ISS);
    expect(v.vct).toBe(VCT);
  });

  it('two presentations of ONE credential are unlinkable, and both verify', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const a = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'nA');
    const b = await present(credential, publicKey, ['age_over_18'], 'https://b.example', 'nB');
    expect(a.proof).not.toBe(b.proof); // no shared handle — the v3 property
    expect((await verifyBbsPresentation({ presentation: a, getIssuerBbsKey, audience: 'https://a.example', nonce: 'nA' })).ok).toBe(true);
    expect((await verifyBbsPresentation({ presentation: b, getIssuerBbsKey, audience: 'https://b.example', nonce: 'nB' })).ok).toBe(true);
  });

  it('rejects a wrong audience or nonce (replay protection)', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const p = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'n1');
    expect((await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://a.example', nonce: 'WRONG' })).ok).toBe(false);
    expect((await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://evil.example', nonce: 'n1' })).ok).toBe(false);
  });

  it('rejects a forged disclosed value (the message binds name+value to its index)', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const p = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'n1');
    const forged = { ...p, disclosed: [{ name: 'age_over_18', value: false }] };
    expect((await verifyBbsPresentation({ presentation: forged, getIssuerBbsKey, audience: 'https://a.example', nonce: 'n1' })).ok).toBe(false);
  });

  it('rejects an expired credential', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup({ age_over_18: true }, { ttlSeconds: 86400, now: Date.now() - 5 * 86400 * 1000 });
    const p = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'n1');
    const v = await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://a.example', nonce: 'n1' });
    expect(v.ok).toBe(false);
    expect(v.error).toBe('credential_expired');
  });
});

describe('BBS presentation wire codec (tagged string)', () => {
  it('round-trips a presentation through encode/decode and tags it', async () => {
    const { publicKey, credential } = await setup();
    const p = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'n1');
    const s = encodeBbsPresentation(p);
    expect(isBbsPresentation(s)).toBe(true);
    expect(s.startsWith('bbs~')).toBe(true);
    expect(decodeBbsPresentation(s)).toEqual(p);
  });

  it('does not mistake an SD-JWT string for a BBS presentation', () => {
    expect(isBbsPresentation('eyJhbG...~disc~kbjwt')).toBe(false); // an SD-JWT presentation
    expect(decodeBbsPresentation('not-a-bbs-string')).toBe(null);
    expect(isBbsPresentation(undefined)).toBe(false);
  });
});

describe('BBS holder binding (non-transferability, v3)', () => {
  const SECRET = new Uint8Array(32).fill(7); // a stand-in master-key-derived holder secret
  const setupBound = async (secret = SECRET) => {
    const { secretKey, publicKey } = await bbsKeyGen();
    const credential = await mintBbsCredential(secretKey, publicKey, {
      iss: ISS,
      vct: VCT,
      claims: { age_over_18: true },
      holderSecret: secret,
      ttlSeconds: 365 * 86400,
    });
    return { publicKey, credential, getIssuerBbsKey: async () => publicKey };
  };
  const presentBound = (credential, publicKey, secret, audience = 'https://a.example', nonce = 'n1') =>
    buildBbsPresentation({ credential, disclose: ['age_over_18'], audience, nonce, issuerPublicKey: publicKey, holderSecret: secret });

  it('marks the credential holderBound and presents + verifies with the right secret', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setupBound();
    expect(credential.holderBound).toBe(true);
    const p = await presentBound(credential, publicKey, SECRET);
    const v = await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://a.example', nonce: 'n1' });
    expect(v.ok).toBe(true);
    expect(v.claims).toEqual({ age_over_18: true });
  });

  it('rejects a presentation built with the WRONG holder secret (a stolen blob)', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setupBound();
    const p = await presentBound(credential, publicKey, new Uint8Array(32).fill(9)); // thief's wrong secret
    const v = await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://a.example', nonce: 'n1' });
    expect(v.ok).toBe(false);
  });

  it('throws if a holder-bound credential is presented without the secret', async () => {
    const { publicKey, credential } = await setupBound();
    await expect(
      buildBbsPresentation({ credential, disclose: ['age_over_18'], audience: 'https://a.example', nonce: 'n1', issuerPublicKey: publicKey }),
    ).rejects.toThrow();
  });

  it('two bound presentations stay unlinkable (proofs differ; the secret is never revealed)', async () => {
    const { publicKey, credential } = await setupBound();
    const p1 = await presentBound(credential, publicKey, SECRET, 'https://a.example', 'nA');
    const p2 = await presentBound(credential, publicKey, SECRET, 'https://b.example', 'nB');
    expect(p1.proof).not.toBe(p2.proof);
  });

  it('an unbound credential still presents (back-compat with pre-binding blobs)', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup(); // minted without holderSecret
    expect(credential.holderBound).toBeUndefined();
    const p = await present(credential, publicKey, ['age_over_18'], 'https://a.example', 'n1'); // no secret
    expect((await verifyBbsPresentation({ presentation: p, getIssuerBbsKey, audience: 'https://a.example', nonce: 'n1' })).ok).toBe(true);
  });
});
