// "Stay unlocked on this device" (opt-in, OFF by default).
//
// Normally the master key lives only in React state, so every reload, new tab, and PWA cold start
// costs a re-typed passkey and a full 256MB Argon2id derive. With this on, the SAME wrapped-master-
// key envelope the vault doc holds is stored once more in IndexedDB — wrapped by a device-local
// AES-GCM key instead of the passkey-derived one. Nothing about the protocol or the vault changes:
// restoring is byte-for-byte the same `decryptData → importMasterKey` the passkey path performs, so
// the restored key is the ordinary extractable master key every HKDF derivation already expects.
//
// The device key is generated NON-EXTRACTABLE, so nothing running on this origin can read its bytes
// or ship the vault key off-device; it can only be used in place, here. That is the whole of the
// guarantee — this is a convenience trade, not a security upgrade:
//   • anyone with access to the unlocked OS profile can open app.kunji.cc and be in the vault;
//   • an XSS on app.kunji.cc becomes persistent rather than bounded to one unlocked session.
// Hence: opt-in, per-device, and cleared by EVERY lock event (contexts/VaultContext.lockVault).
// A saved session survives closing the app — never an explicit lock, an idle lock, or sign-out.

import { encryptData, decryptData, exportKey, importMasterKey } from '../lib/crypto';
import { autoLockMs, getSessionSeen, setSessionSeen } from '../lib/sessionPrefs';

export const SESSION_VERSION = 1;
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days, then the passkey is required again

const DB_NAME = 'kunji-session';
const STORE = 'session';
const RECORD_KEY = 'current';

/**
 * Wrap an unlocked master key under a fresh non-extractable device key. Pure crypto, no storage —
 * so the policy below is unit-testable without IndexedDB.
 */
export const sealSession = async (masterKey, uid, now = Date.now(), ttlMs = SESSION_TTL_MS) => {
  const wrapKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const expiresAt = now + ttlMs;
  const jwk = await exportKey(masterKey);
  const blob = await encryptData({ jwk, uid, expiresAt }, wrapKey);
  return { v: SESSION_VERSION, uid, expiresAt, wrapKey, blob };
};

/**
 * Unwrap a sealed record back to the master key, or null if it's absent, foreign, expired, or
 * corrupt. The uid and expiry INSIDE the ciphertext are authoritative — the copies on the record
 * are unauthenticated (any script on this origin can rewrite an IndexedDB row) and serve only as
 * cheap pre-checks, so editing them can't widen a session or hand it to another account.
 */
export const openSession = async (record, uid, now = Date.now()) => {
  if (!record || record.v !== SESSION_VERSION) return null;
  if (record.uid !== uid || !(record.expiresAt > now)) return null;
  const payload = await decryptData(record.blob, record.wrapKey);
  if (!payload || payload.uid !== uid || !(payload.expiresAt > now)) return null;
  return importMasterKey(payload.jwk);
};

/**
 * Does the idle policy reject a session last seen at `seenAt`? (S46.) The auto-lock setting is a
 * statement about the VAULT, not about tabs — a saved session must honour it across app closures
 * too, or a user who chose "lock after 15 minutes" gets 30 days of unlocked vault by quitting.
 * The idle timer in App.jsx only ticks while a page is open, so this is the same policy applied to
 * wall-clock time. Fails closed: `seenAt` 0 means a lock revoked it (or storage is unreadable).
 */
export const sessionIdleExpired = (seenAt, idleMs, now) => {
  if (!seenAt) return true;
  if (idleMs == null) return false; // auto-lock off — only the 30-day TTL bounds the session
  return now - seenAt > idleMs;
};

// Minimal IndexedDB access for the single session record. IndexedDB rather than localStorage
// because a CryptoKey is structured-cloneable but not stringifiable — that is exactly what lets the
// device key stay non-extractable. Resolves on transaction commit, so a write is durable by then.
const withStore = (mode, fn) =>
  new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => {
      if (!open.result.objectStoreNames.contains(STORE)) open.result.createObjectStore(STORE);
    };
    open.onerror = () => reject(open.error);
    open.onblocked = () => reject(new Error('IDB_BLOCKED'));
    open.onsuccess = () => {
      const db = open.result;
      let tx;
      let req;
      try {
        tx = db.transaction(STORE, mode);
        req = fn(tx.objectStore(STORE));
      } catch (e) {
        db.close();
        reject(e);
        return;
      }
      tx.oncomplete = () => {
        db.close();
        resolve(req?.result ?? null);
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
      tx.onabort = () => {
        db.close();
        reject(tx.error || new Error('IDB_ABORT'));
      };
    };
  });

/** Save the unlocked master key for this device. Returns false if storage is unavailable. */
export const armDeviceSession = async (masterKey, uid) => {
  try {
    const record = await sealSession(masterKey, uid);
    await withStore('readwrite', (s) => s.put(record, RECORD_KEY));
    setSessionSeen(Date.now()); // starts the idle clock (and lifts any prior revocation)
    return true;
  } catch {
    return false; // private mode / blocked storage — the caller reverts the preference
  }
};

/**
 * Restore the master key saved on this device, or null. A record that fails any check is deleted
 * rather than left to fail again on the next load.
 */
export const restoreDeviceSession = async (uid) => {
  try {
    // Check the idle policy FIRST: it's the synchronous localStorage marker, so it still holds if a
    // lock's async IndexedDB delete never committed (frozen or killed tab).
    if (sessionIdleExpired(getSessionSeen(), autoLockMs(), Date.now())) {
      await clearDeviceSession();
      return null;
    }
    const record = await withStore('readonly', (s) => s.get(RECORD_KEY));
    if (!record) return null;
    const masterKey = await openSession(record, uid);
    if (!masterKey) await clearDeviceSession();
    else setSessionSeen(Date.now()); // restart the idle clock for this run
    return masterKey;
  } catch {
    return null;
  }
};

/** Forget the saved session. Safe to call when there isn't one. */
export const clearDeviceSession = async () => {
  try {
    await withStore('readwrite', (s) => s.delete(RECORD_KEY));
  } catch {
    /* nothing stored, or storage unavailable — either way there's no session to restore */
  }
};
