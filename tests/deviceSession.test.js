import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  sealSession,
  openSession,
  sessionIdleExpired,
  SESSION_TTL_MS,
  SESSION_VERSION,
} from '../src/services/deviceSession.js';
import {
  generateMasterKey,
  deriveVaultId,
  encryptData,
  decryptData,
} from '../src/lib/crypto/index.js';
import {
  AUTO_LOCK_DEFAULT_MIN,
  autoLockMs,
  getAutoLockMinutes,
  getLockOnHidden,
  getSessionSeen,
  getStayUnlocked,
  parseAutoLockMinutes,
  revokeSessionSeen,
  setAutoLockMinutes,
  setLockOnHidden,
  setSessionSeen,
  setStayUnlocked,
} from '../src/lib/sessionPrefs.js';

// "Stay unlocked on this device" — the master key is re-wrapped under a non-extractable device key
// and parked in IndexedDB. seal/open are the whole policy; the IndexedDB layer around them is a
// plain get/put. What must hold: the restored key is the SAME master key (byte-identical
// derivations, or every app identity changes), and only the intended account, within the intended
// window, can open it — including against a record edited in place, since IndexedDB rows are
// rewritable by anything running on the origin.

const UID = 'uid-alice';
const NOW = 1_700_000_000_000;

describe('sealSession / openSession round-trip', () => {
  it('restores the same master key — same vaultId, and it still decrypts existing ciphertext', async () => {
    const master = await generateMasterKey();
    const before = await deriveVaultId(master);
    const secret = await encryptData({ hello: 'vault' }, master);

    const restored = await openSession(await sealSession(master, UID, NOW), UID, NOW + 1000);

    expect(restored).not.toBeNull();
    expect(await deriveVaultId(restored)).toBe(before);
    expect(await decryptData(secret, restored)).toEqual({ hello: 'vault' });
  });

  it('restores an EXTRACTABLE key — deriveVaultId and every Ed25519/HKDF derivation exportKey it', async () => {
    const master = await generateMasterKey();
    const restored = await openSession(await sealSession(master, UID, NOW), UID, NOW);
    expect(restored.extractable).toBe(true);
  });

  it('wraps under a NON-extractable device key, so nothing on the origin can read it off-device', async () => {
    const record = await sealSession(await generateMasterKey(), UID, NOW);
    expect(record.wrapKey.extractable).toBe(false);
    await expect(window.crypto.subtle.exportKey('raw', record.wrapKey)).rejects.toThrow();
  });

  it('stores no plaintext key material on the record', async () => {
    const record = await sealSession(await generateMasterKey(), UID, NOW);
    expect(JSON.stringify({ ...record, wrapKey: undefined })).not.toMatch(/"k"|kty/);
    expect(record).toMatchObject({ v: SESSION_VERSION, uid: UID, expiresAt: NOW + SESSION_TTL_MS });
  });
});

describe('openSession rejects', () => {
  const seal = (uid = UID, now = NOW, ttl = SESSION_TTL_MS) =>
    generateMasterKey().then((k) => sealSession(k, uid, now, ttl));

  it('a missing record', async () => {
    expect(await openSession(null, UID, NOW)).toBeNull();
    expect(await openSession(undefined, UID, NOW)).toBeNull();
  });

  it('another account', async () => {
    expect(await openSession(await seal(), 'uid-mallory', NOW)).toBeNull();
  });

  it('an expired session', async () => {
    expect(await openSession(await seal(), UID, NOW + SESSION_TTL_MS + 1)).toBeNull();
  });

  it('a future version (a record this build does not understand)', async () => {
    const record = await seal();
    expect(await openSession({ ...record, v: SESSION_VERSION + 1 }, UID, NOW)).toBeNull();
  });

  it('a record whose uid was rewritten in place — the sealed uid is authoritative', async () => {
    const record = await seal('uid-alice');
    // Outer uid now matches the attacker; only the ciphertext still names Alice.
    expect(await openSession({ ...record, uid: 'uid-mallory' }, 'uid-mallory', NOW)).toBeNull();
  });

  it('a record whose expiry was extended in place — the sealed expiry is authoritative', async () => {
    const record = await seal(UID, NOW, -1000); // already expired when sealed
    const extended = { ...record, expiresAt: NOW + SESSION_TTL_MS };
    expect(await openSession(extended, UID, NOW)).toBeNull();
  });

  it('a blob that does not match the record wrap key', async () => {
    const a = await seal();
    const b = await seal();
    expect(await openSession({ ...a, blob: b.blob }, UID, NOW)).toBeNull();
  });
});

// S46: the auto-lock setting is a statement about the vault, so a saved session has to honour it
// across app closures — not only while a tab happens to be open ticking the idle timer.
describe('sessionIdleExpired (S46 — auto-lock applies to a saved session)', () => {
  const MIN = 60000;

  it('rejects a session idle for longer than the auto-lock setting', () => {
    // The reported bug: "auto-lock: 15 min", app closed for 3 days, restored with no passkey.
    expect(sessionIdleExpired(NOW, 15 * MIN, NOW + 3 * 86400000)).toBe(true);
  });

  it('accepts a session still inside the window', () => {
    expect(sessionIdleExpired(NOW, 15 * MIN, NOW + 14 * MIN)).toBe(false);
    expect(sessionIdleExpired(NOW, 15 * MIN, NOW + 15 * MIN)).toBe(false); // boundary is inclusive
    expect(sessionIdleExpired(NOW, 15 * MIN, NOW + 15 * MIN + 1)).toBe(true);
  });

  it('leaves the 30-day TTL as the only bound when auto-lock is off', () => {
    expect(sessionIdleExpired(NOW, null, NOW + 3 * 86400000)).toBe(false);
  });

  it('fails closed on a revoked marker — a lock holds even if its IndexedDB delete never committed', () => {
    expect(sessionIdleExpired(0, null, NOW)).toBe(true); // revoked beats "auto-lock off"
    expect(sessionIdleExpired(0, 15 * MIN, NOW)).toBe(true);
  });
});

describe('sessionPrefs', () => {
  const store = new Map();
  beforeEach(() => {
    store.clear();
    globalThis.localStorage = {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    };
  });
  afterEach(() => {
    delete globalThis.localStorage;
  });

  it('falls back to the default for unset and unparseable auto-lock values', () => {
    expect(parseAutoLockMinutes(null)).toBe(AUTO_LOCK_DEFAULT_MIN);
    expect(parseAutoLockMinutes('')).toBe(AUTO_LOCK_DEFAULT_MIN);
    // The old inline parseInt turned these into NaN, which disabled auto-lock outright.
    expect(parseAutoLockMinutes('later')).toBe(AUTO_LOCK_DEFAULT_MIN);
    expect(parseAutoLockMinutes('-5')).toBe(AUTO_LOCK_DEFAULT_MIN);
    expect(parseAutoLockMinutes('15')).toBe(15);
    expect(parseAutoLockMinutes('0')).toBe(0);
  });

  it('maps minutes to a timeout, with 0 meaning never', () => {
    expect(autoLockMs(15)).toBe(900000);
    expect(autoLockMs(0)).toBeNull();
  });

  it('round-trips each preference, and defaults to the safe setting', () => {
    expect(getStayUnlocked()).toBe(false); // opt-in, never on by default
    expect(getLockOnHidden()).toBe(false);
    expect(getAutoLockMinutes()).toBe(AUTO_LOCK_DEFAULT_MIN);

    setStayUnlocked(true);
    setLockOnHidden(true);
    setAutoLockMinutes(60);
    expect(getStayUnlocked()).toBe(true);
    expect(getLockOnHidden()).toBe(true);
    expect(getAutoLockMinutes()).toBe(60);

    setStayUnlocked(false);
    expect(getStayUnlocked()).toBe(false);
  });

  it('clamps an absurd hand-set auto-lock value (setTimeout wraps past 2^31-1 and fires at once)', () => {
    expect(parseAutoLockMinutes('999999999')).toBe(30 * 24 * 60);
    // The minutes clamp alone is NOT enough: 30 days is 2.59e9 ms, still over the timer ceiling.
    expect(autoLockMs(parseAutoLockMinutes('999999999'))).toBeLessThanOrEqual(2 ** 31 - 1);
    expect(autoLockMs(1200)).toBe(72000000); // every real option is far below the clamp
  });

  it('tracks the idle marker, and revokes it synchronously', () => {
    expect(getSessionSeen()).toBe(0); // unset ⇒ fails closed
    setSessionSeen(NOW);
    expect(getSessionSeen()).toBe(NOW);
    revokeSessionSeen();
    expect(getSessionSeen()).toBe(0);
  });

  it('survives blocked storage (private mode) without throwing', () => {
    globalThis.localStorage = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
    };
    expect(() => setStayUnlocked(true)).not.toThrow();
    expect(getStayUnlocked()).toBe(false); // unreadable ⇒ treated as off
    expect(getAutoLockMinutes()).toBe(AUTO_LOCK_DEFAULT_MIN);
  });
});
