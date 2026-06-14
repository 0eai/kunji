import { describe, it, expect, vi } from 'vitest';

// credentials.js pulls in Firebase at import; stub it so the service helpers run in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));

import {
  groupByPool,
  selectForPresentation,
  holderKeyFor,
  spendIfOneTime,
} from '../src/services/credentials.js';
import {
  mintCredential,
  buildPresentation,
  verifyCredentialPresentation,
  parseSdJwt,
  holderJwkFor,
  deriveCredentialHolderKey,
} from '../src/lib/vc.js';
import {
  generateMasterKey,
  generateEd25519KeyPair,
  exportEd25519SecretKey,
} from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';

// Unlinkability v2 (verified-credentials.md §7): a batch of one-time-use copies, each bound to a
// DISTINCT random holder key + minted with fresh salts, so no two presentations share a correlation
// handle (issuer signature OR holder key `cnf.jwk`). The wallet spends one copy per presentation.

const ISS = 'https://issuer.example';
const VCT = 'https://issuer.example/age';
const KID = 'issuer-2026';

const mintCopy = async (issuerSecretKey, holderPublicKey) =>
  mintCredential(issuerSecretKey, {
    kid: KID,
    iss: ISS,
    vct: VCT,
    claims: { age_over_18: true },
    holderJwk: holderJwkFor(holderPublicKey),
    status: { uri: `${ISS}/status/1`, idx: 1 },
    ttlSeconds: 3600,
  });

describe('batch one-time credentials are unlinkable (the heart of v2)', () => {
  it('N copies share no issuer signature and no holder key, yet each presents + verifies', async () => {
    const issuer = generateEd25519KeyPair();
    const getIssuerKeys = async () => [{ ...okpJwk(issuer.publicKey), kid: KID }];
    const N = 5;
    const copies = [];
    for (let i = 0; i < N; i++) {
      const holder = generateEd25519KeyPair();
      copies.push({ sdjwt: await mintCopy(issuer.secretKey, holder.publicKey), holder });
    }

    // No two copies share a correlation handle.
    expect(new Set(copies.map((c) => parseSdJwt(c.sdjwt).issuerJws)).size).toBe(N);
    expect(new Set(copies.map((c) => parseSdJwt(c.sdjwt).issuerClaims.cnf.jwk.x)).size).toBe(N);

    // Each copy presents to a different verifier and verifies independently.
    for (let i = 0; i < N; i++) {
      const audience = `https://verifier-${i}.example`;
      const nonce = `nonce-${i}-`.padEnd(16, 'x');
      const presentation = await buildPresentation({
        sdjwt: copies[i].sdjwt,
        disclose: ['age_over_18'],
        audience,
        nonce,
        holderSecretKey: copies[i].holder.secretKey,
      });
      const v = await verifyCredentialPresentation({ presentation, getIssuerKeys, audience, nonce });
      expect(v.ok).toBe(true);
      expect(v.claims.age_over_18).toBe(true);
    }
  });

  it('contrast: reusing ONE credential shares both handles (the v1 linkability v2 removes)', async () => {
    const issuer = generateEd25519KeyPair();
    const holder = generateEd25519KeyPair();
    const sdjwt = await mintCopy(issuer.secretKey, holder.publicKey);
    const a = parseSdJwt(sdjwt);
    const b = parseSdJwt(sdjwt);
    expect(a.issuerJws).toBe(b.issuerJws); // same signature across presentations
    expect(a.issuerClaims.cnf.jwk.x).toBe(b.issuerClaims.cnf.jwk.x); // same holder key
  });
});

describe('groupByPool', () => {
  it('groups one-time copies by poolId with a remaining count; a legacy cred is its own group', () => {
    const held = [
      { credId: 'a1', vct: VCT, iss: ISS, poolId: 'P', oneTime: true, receivedAt: 3 },
      { credId: 'a2', vct: VCT, iss: ISS, poolId: 'P', oneTime: true, receivedAt: 3 },
      { credId: 'a3', vct: VCT, iss: ISS, poolId: 'P', oneTime: true, receivedAt: 3 },
      { credId: 'legacy', vct: VCT, iss: ISS, receivedAt: 1 }, // v1: no poolId / oneTime
    ];
    const pools = groupByPool(held);
    expect(pools).toHaveLength(2);
    const pool = pools.find((g) => g.key === 'P');
    expect(pool.remaining).toBe(3);
    expect(pool.oneTime).toBe(true);
    const legacy = pools.find((g) => g.key === 'legacy');
    expect(legacy.remaining).toBe(1);
    expect(legacy.oneTime).toBe(false);
  });

  it('returns [] for an empty held list', () => {
    expect(groupByPool([])).toEqual([]);
  });
});

describe('selectForPresentation', () => {
  it('collapses a multi-copy pool to ONE match per logical credential (not five identical rows)', () => {
    const held = [
      { credId: 'a1', vct: 'age', iss: ISS, sdjwt: 'x', poolId: 'P', oneTime: true },
      { credId: 'a2', vct: 'age', iss: ISS, sdjwt: 'x', poolId: 'P', oneTime: true },
      { credId: 'a3', vct: 'age', iss: ISS, sdjwt: 'x', poolId: 'P', oneTime: true },
    ];
    const out = selectForPresentation(held, ['vc:age#age_over_18']);
    expect(out).toHaveLength(1);
    expect(out[0].disclose).toEqual(['age_over_18']);
    expect(out[0].cred.poolId).toBe('P');
  });

  it('still selects a legacy (poolId-less) credential', () => {
    const held = [{ credId: 'legacy', vct: 'age', iss: ISS, sdjwt: 'x' }];
    expect(selectForPresentation(held, ['vc:age'])).toHaveLength(1);
  });
});

describe('holderKeyFor', () => {
  it('uses the stored per-copy holderSk for a v2 one-time copy', async () => {
    const kp = generateEd25519KeyPair();
    const sk = await holderKeyFor(null, { iss: ISS, holderSk: exportEd25519SecretKey(kp.secretKey) });
    expect(Array.from(sk)).toEqual(Array.from(kp.secretKey));
  });

  it('falls back to the derived per-issuer key for a legacy credential', async () => {
    const master = await generateMasterKey();
    const sk = await holderKeyFor(master, { iss: ISS }); // no holderSk
    const { secretKey } = await deriveCredentialHolderKey(master, ISS);
    expect(Array.from(sk)).toEqual(Array.from(secretKey));
  });
});

describe('spendIfOneTime', () => {
  it('deletes a one-time copy (op:delete, kind:credential) after a successful presentation', async () => {
    const master = await generateMasterKey();
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({}) }));
    vi.stubGlobal('fetch', fetchMock);
    await spendIfOneTime(master, { credId: 'abc123', iss: ISS, oneTime: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.op).toBe('delete');
    expect(body.appId).toBe('abc123');
    expect(body.kind).toBe('credential');
    vi.unstubAllGlobals();
  });

  it('leaves a v1 / legacy (reusable) credential in place', async () => {
    const master = await generateMasterKey();
    const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({}) }));
    vi.stubGlobal('fetch', fetchMock);
    await spendIfOneTime(master, { credId: 'abc123', iss: ISS }); // no oneTime flag
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
