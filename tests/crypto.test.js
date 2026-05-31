import { describe, it, expect } from 'vitest';
import {
  generateMasterKey,
  exportKey,
  importMasterKey,
  encryptData,
  decryptData,
  deriveKeyArgon2id,
  deriveKeyFromPasskey,
  deriveVaultId,
  deriveAppKeyPair,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
  verifyEd25519Signature,
  ARGON2_DEFAULTS,
  ARGON2_LEGACY,
  argon2ParamsFromDoc,
  argon2DocFields,
} from '../src/lib/crypto/index.js';
import { normalizeDomain } from '../src/lib/crypto/helpers.js';

// Fast Argon2 params for tests (security level is irrelevant here — we only assert behavior).
const ARGON_TEST = { memorySize: 8192, iterations: 1, parallelism: 1 };
const HEX64 = /^[0-9a-f]{64}$/;

describe('AES-GCM encrypt/decrypt', () => {
  it('round-trips an object', async () => {
    const key = await generateMasterKey();
    const enc = await encryptData({ hello: 'world', n: 42 }, key);
    expect(enc).toHaveProperty('iv');
    expect(enc).toHaveProperty('data');
    expect(await decryptData(enc, key)).toEqual({ hello: 'world', n: 42 });
  });

  it('returns null with the wrong key (auth-tag failure)', async () => {
    const enc = await encryptData({ a: 1 }, await generateMasterKey());
    expect(await decryptData(enc, await generateMasterKey())).toBeNull();
  });

  it('uses a fresh random IV per call', async () => {
    const key = await generateMasterKey();
    const a = await encryptData({ a: 1 }, key);
    const b = await encryptData({ a: 1 }, key);
    expect(a.iv).not.toEqual(b.iv);
  });
});

describe('master key export/import', () => {
  it('survives a JWK export → import round-trip', async () => {
    const key = await generateMasterKey();
    const enc = await encryptData({ x: 1 }, key);
    const reimported = await importMasterKey(await exportKey(key));
    expect(await decryptData(enc, reimported)).toEqual({ x: 1 });
  });
});

describe('Argon2id KDF', () => {
  it('is deterministic for the same passkey/salt/params', async () => {
    const k1 = await deriveKeyArgon2id('correct horse', 'unit-test-salt-A', ARGON_TEST);
    const k2 = await deriveKeyArgon2id('correct horse', 'unit-test-salt-A', ARGON_TEST);
    const enc = await encryptData({ ok: true }, k1);
    expect(await decryptData(enc, k2)).toEqual({ ok: true }); // same derived key
  });

  it('a wrong passkey derives a different key', async () => {
    const good = await deriveKeyArgon2id('right', 'unit-test-salt-A', ARGON_TEST);
    const bad = await deriveKeyArgon2id('wrong', 'unit-test-salt-A', ARGON_TEST);
    const enc = await encryptData({ ok: true }, good);
    expect(await decryptData(enc, bad)).toBeNull();
  });

  it('different params derive a different key (param binding)', async () => {
    const k1 = await deriveKeyArgon2id('pw', 'unit-test-salt-A', { ...ARGON_TEST, iterations: 1 });
    const k2 = await deriveKeyArgon2id('pw', 'unit-test-salt-A', { ...ARGON_TEST, iterations: 2 });
    const enc = await encryptData({ ok: true }, k1);
    expect(await decryptData(enc, k2)).toBeNull();
  });
});

describe('PBKDF2 KDF (legacy)', () => {
  it('round-trips with matching iterations', async () => {
    const k1 = await deriveKeyFromPasskey('pw', 'salt-B', 1000);
    const k2 = await deriveKeyFromPasskey('pw', 'salt-B', 1000);
    const enc = await encryptData({ v: 1 }, k1);
    expect(await decryptData(enc, k2)).toEqual({ v: 1 });
  });
});

describe('argon2 param doc helpers', () => {
  it('falls back to legacy params when the doc has no argon2 field', () => {
    expect(argon2ParamsFromDoc({})).toEqual(ARGON2_LEGACY);
  });
  it('round-trips doc fields ↔ params', () => {
    const fields = argon2DocFields(ARGON2_DEFAULTS);
    expect(fields).toEqual({ m: 262144, t: 4, p: 1 });
    expect(argon2ParamsFromDoc({ argon2: fields })).toEqual(ARGON2_DEFAULTS);
  });
});

describe('deriveVaultId', () => {
  it('is 64-hex and deterministic per master key', async () => {
    const key = await generateMasterKey();
    const a = await deriveVaultId(key);
    const b = await deriveVaultId(key);
    expect(a).toMatch(HEX64);
    expect(a).toBe(b);
  });

  it('differs across master keys', async () => {
    const a = await deriveVaultId(await generateMasterKey());
    const b = await deriveVaultId(await generateMasterKey());
    expect(a).not.toBe(b);
  });
});

describe('deriveAppKeyPair', () => {
  it('is deterministic per (master key, domain)', async () => {
    const key = await generateMasterKey();
    const p1 = exportEd25519PublicKey((await deriveAppKeyPair(key, 'cloq.cc')).publicKey);
    const p2 = exportEd25519PublicKey((await deriveAppKeyPair(key, 'cloq.cc')).publicKey);
    expect(p1).toBe(p2);
  });

  it('differs across domains', async () => {
    const key = await generateMasterKey();
    const a = exportEd25519PublicKey((await deriveAppKeyPair(key, 'a.com')).publicKey);
    const b = exportEd25519PublicKey((await deriveAppKeyPair(key, 'b.com')).publicKey);
    expect(a).not.toBe(b);
  });

  it('normalizes the domain (case / trailing dot / default port collapse to one identity)', async () => {
    const key = await generateMasterKey();
    const base = exportEd25519PublicKey((await deriveAppKeyPair(key, 'example.com')).publicKey);
    for (const variant of ['Example.com', 'EXAMPLE.COM', 'example.com.', 'example.com:443']) {
      expect(exportEd25519PublicKey((await deriveAppKeyPair(key, variant)).publicKey)).toBe(base);
    }
  });

  it('the vault write key is distinct from any app key', async () => {
    const key = await generateMasterKey();
    const write = exportEd25519PublicKey((await deriveVaultWriteKeyPair(key)).publicKey);
    const app = exportEd25519PublicKey((await deriveAppKeyPair(key, 'example.com')).publicKey);
    expect(write).not.toBe(app);
  });
});

describe('Ed25519 sign/verify (canonical JSON)', () => {
  it('verifies a valid signature and rejects a tampered payload', async () => {
    const { secretKey, publicKey } = await deriveAppKeyPair(await generateMasterKey(), 'x.com');
    const payload = { a: 1, b: 'two', c: true };
    const sig = signWithEd25519(payload, secretKey);
    expect(verifyEd25519Signature(payload, sig, publicKey)).toBe(true);
    expect(verifyEd25519Signature({ ...payload, a: 2 }, sig, publicKey)).toBe(false);
  });

  it('is independent of key insertion order (canonical)', async () => {
    const { secretKey } = await deriveAppKeyPair(await generateMasterKey(), 'x.com');
    const s1 = signWithEd25519({ a: 1, b: 2 }, secretKey);
    const s2 = signWithEd25519({ b: 2, a: 1 }, secretKey);
    expect(s1).toBe(s2);
  });
});

describe('normalizeDomain', () => {
  it('lowercases, trims, strips trailing dot + default ports', () => {
    expect(normalizeDomain('Example.COM')).toBe('example.com');
    expect(normalizeDomain('  x.com  ')).toBe('x.com');
    expect(normalizeDomain('x.com.')).toBe('x.com');
    expect(normalizeDomain('x.com:443')).toBe('x.com');
    expect(normalizeDomain('x.com:80')).toBe('x.com');
    expect(normalizeDomain('x.com:8443')).toBe('x.com:8443'); // non-default port kept
  });
});
