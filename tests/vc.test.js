import { describe, it, expect } from 'vitest';
import {
  mintCredential,
  buildPresentation,
  verifyCredentialPresentation,
  parseSdJwt,
  holderJwkFor,
  matchCredentialsByScope,
  deriveCredentialHolderKey,
} from '../src/lib/vc.js';
import {
  generateMasterKey,
  generateEd25519KeyPair,
  deriveAppKeyPair,
  exportEd25519PublicKey,
} from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';

const ISS = 'https://issuer.example';
const VCT = 'https://issuer.example/age';
const KID = 'issuer-2026';
const AUD = 'app.example.com';
const NONCE = 'n'.repeat(64);

// Issuer key getter (offline) — what the RP would fetch from /.well-known/kunji-issuer.json.
const issuerKeysFor = (issuerPub) => async () => [{ ...okpJwk(issuerPub), kid: KID }];

// Mint a credential bound to a freshly-derived holder key; return everything a test needs.
const setup = async ({ claims = { age_over_18: true, name: 'Ada' }, status, ttlSeconds = 3600, now } = {}) => {
  const issuer = generateEd25519KeyPair();
  const master = await generateMasterKey();
  const holder = await deriveCredentialHolderKey(master, ISS);
  const credential = await mintCredential(issuer.secretKey, {
    kid: KID,
    iss: ISS,
    vct: VCT,
    claims,
    holderJwk: holderJwkFor(holder.publicKey),
    status,
    ttlSeconds,
    now,
  });
  return { issuer, master, holder, credential, getIssuerKeys: issuerKeysFor(issuer.publicKey) };
};

const present = (credential, holder, over = {}) =>
  buildPresentation({
    sdjwt: credential,
    disclose: ['age_over_18'],
    audience: AUD,
    nonce: NONCE,
    holderSecretKey: holder.secretKey,
    ...over,
  });

const verify = (presentation, getIssuerKeys, over = {}) =>
  verifyCredentialPresentation({
    presentation,
    getIssuerKeys,
    audience: AUD,
    nonce: NONCE,
    checkStatus: async () => true,
    ...over,
  });

describe('deriveCredentialHolderKey', () => {
  it('is deterministic per (master, issuer) and separated from other derivations', async () => {
    const master = await generateMasterKey();
    const a = await deriveCredentialHolderKey(master, ISS);
    const b = await deriveCredentialHolderKey(master, ISS);
    const other = await deriveCredentialHolderKey(master, 'https://other.example');
    const app = await deriveAppKeyPair(master, 'app.example.com');
    expect(exportEd25519PublicKey(a.publicKey)).toBe(exportEd25519PublicKey(b.publicKey));
    expect(exportEd25519PublicKey(a.publicKey)).not.toBe(exportEd25519PublicKey(other.publicKey));
    expect(exportEd25519PublicKey(a.publicKey)).not.toBe(exportEd25519PublicKey(app.publicKey));
  });
});

describe('verified credential — happy path', () => {
  it('mint → present (selective) → verify resolves only the disclosed claim', async () => {
    const { credential, holder, getIssuerKeys } = await setup();
    const r = await verify(await present(credential, holder), getIssuerKeys);
    expect(r).toMatchObject({ ok: true, iss: ISS, vct: VCT, claims: { age_over_18: true } });
    expect(r.claims.name).toBeUndefined(); // not disclosed → not revealed
  });

  it('parseSdJwt exposes the held disclosures by name (without revealing them to an RP)', async () => {
    const { credential } = await setup();
    const parsed = parseSdJwt(credential);
    expect(parsed.disclosures.map((d) => d.name).sort()).toEqual(['age_over_18', 'name']);
    expect(parsed.issuerClaims.iss).toBe(ISS);
  });
});

describe('verified credential — rejections', () => {
  it('rejects a wrong audience / nonce (replay protection)', async () => {
    const { credential, holder, getIssuerKeys } = await setup();
    const p = await present(credential, holder);
    expect(await verify(p, getIssuerKeys, { audience: 'evil.com' })).toMatchObject({ ok: false, error: 'kb_audience_mismatch' });
    expect(await verify(p, getIssuerKeys, { nonce: 'd'.repeat(64) })).toMatchObject({ ok: false, error: 'kb_nonce_mismatch' });
  });

  it('rejects a revoked credential (StatusList false) and fails closed if the check throws', async () => {
    const { credential, holder, getIssuerKeys } = await setup({ status: { uri: `${ISS}/status/1`, idx: 7 } });
    const p = await present(credential, holder);
    expect(await verify(p, getIssuerKeys, { checkStatus: async () => false })).toMatchObject({ ok: false, error: 'revoked' });
    expect(await verify(p, getIssuerKeys, { checkStatus: async () => { throw new Error('down'); } })).toMatchObject({ ok: false, error: 'status_check_failed' });
  });

  it('rejects an unknown / wrong issuer key', async () => {
    const { credential, holder } = await setup();
    const attacker = generateEd25519KeyPair();
    const r = await verify(await present(credential, holder), issuerKeysFor(attacker.publicKey));
    expect(r).toMatchObject({ ok: false, error: 'bad_issuer_signature' });
  });

  it('rejects an expired credential', async () => {
    const { credential, holder, getIssuerKeys } = await setup({ ttlSeconds: 1 });
    const r = await verify(await present(credential, holder), getIssuerKeys, { now: Date.now() + 10_000 });
    expect(r).toMatchObject({ ok: false, error: 'credential_expired' });
  });

  it('rejects a KB-JWT signed by the wrong holder key (holder-of-key)', async () => {
    const { credential, getIssuerKeys } = await setup();
    const impostor = generateEd25519KeyPair();
    const p = await present(credential, { secretKey: impostor.secretKey });
    expect(await verify(p, getIssuerKeys)).toMatchObject({ ok: false, error: 'bad_key_binding' });
  });

  it('rejects a disclosure that does not hash into _sd', async () => {
    const a = await setup();
    const b = await setup({ claims: { age_over_18: false } });
    const bRaw = parseSdJwt(b.credential).disclosures[0].raw; // a real disclosure from a DIFFERENT credential
    const pa = await buildPresentation({ sdjwt: a.credential, disclose: [], audience: AUD, nonce: NONCE, holderSecretKey: a.holder.secretKey });
    const parts = pa.split('~'); // [issuerJws, '', kb]
    const spliced = [parts[0], bRaw, parts[parts.length - 1]].join('~');
    expect(await verify(spliced, a.getIssuerKeys)).toMatchObject({ ok: false, error: 'disclosure_not_in_sd' });
  });
});

describe('matchCredentialsByScope', () => {
  const held = [
    { vct: 'age', iss: 'https://i1' },
    { vct: 'email', iss: 'https://i1' },
  ];
  it('matches by vct and optional @issuer', () => {
    expect(matchCredentialsByScope(held, ['login', 'vc:age'])).toEqual([{ vct: 'age', iss: 'https://i1' }]);
    expect(matchCredentialsByScope(held, ['vc:age@https://i1'])).toEqual([{ vct: 'age', iss: 'https://i1' }]);
    expect(matchCredentialsByScope(held, ['vc:age@https://other'])).toEqual([]);
    expect(matchCredentialsByScope(held, ['login', 'profile'])).toEqual([]);
  });
});
