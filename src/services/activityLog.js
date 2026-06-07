import {
  collection,
  addDoc,
  query,
  orderBy,
  limit,
  onSnapshot,
  serverTimestamp,
} from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  encryptData,
  decryptData,
  deriveVaultId,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../lib/crypto';
import { deviceLabel } from '../lib/deviceInfo';
import { getSessionIp, setSessionIp } from '../lib/sessionMeta';

const VAULT_WRITE_URL = import.meta.env.VITE_VAULT_WRITE_URL || '/vault/write';

const activityCol = (uid) => collection(db, 'users', uid, 'activity_log'); // legacy per-device log
const vaultActivityCol = (vaultId) => collection(db, 'vaults', vaultId, 'activity'); // shared log

const tsMs = (t) =>
  t && typeof t.toMillis === 'function' ? t.toMillis() : t && t.seconds ? t.seconds * 1000 : 0;

// Signed write of one ENCRYPTED activity entry to the shared vault log (kind:'activity').
// Mirrors services/profile.js writeProfile: the function never sees the master key or plaintext,
// only the ciphertext + a vault-write signature. It echoes the caller IP, which we cache for
// subsequent entries (it is never persisted server-side; we encrypt it into the payload).
const writeVaultActivity = async (cryptoKey, encryptedPayload) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const entryId = crypto.randomUUID(); // SAFE_ID-compatible (hex + dashes)
  const timestamp = Date.now();
  const signed = {
    appId: entryId,
    doc: encryptedPayload,
    kind: 'activity',
    op: 'set',
    publicKey: publicKeyB64,
    timestamp,
    vaultId,
  };
  const signedToken = signWithEd25519(signed, secretKey);

  const resp = await fetch(VAULT_WRITE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      vaultId,
      op: 'set',
      appId: entryId,
      kind: 'activity',
      doc: encryptedPayload,
      publicKey: publicKeyB64,
      signedToken,
      timestamp,
    }),
  });
  if (!resp.ok) throw new Error('activity_write_failed:' + resp.status);
  const data = await resp.json().catch(() => ({}));
  if (data?.ip) setSessionIp(data.ip);
};

// `extra` is merged into the (encrypted) payload — e.g. { domain } to tag app events.
// Every event also carries a coarse `device` label (browser · OS) so the log reads as
// "was this me?"; an `extra.device` from the caller would win.
//
// With a cryptoKey the entry goes to the SHARED, encrypted vault log (visible on every linked
// device) and carries the session IP when known. Without a key (pre-unlock events), or on any
// failure, it falls back to the legacy per-device log — so events are never lost and the client
// is safe to deploy before/after the function gains kind:'activity'.
export const logActivity = async (
  uid,
  action,
  type = 'success',
  icon = 'CheckCircle',
  cryptoKey = null,
  extra = {},
) => {
  if (!uid) return;
  const payload = { action, type, icon, device: deviceLabel(), ...extra };

  if (cryptoKey) {
    try {
      const ip = getSessionIp();
      const encrypted = await encryptData(ip ? { ...payload, ip } : payload, cryptoKey);
      await writeVaultActivity(cryptoKey, encrypted);
      return;
    } catch (e) {
      console.warn('Vault activity write failed, falling back to device log:', e);
    }
  }

  try {
    const stored = cryptoKey
      ? { ...(await encryptData(payload, cryptoKey)), createdAt: serverTimestamp() }
      : { ...payload, createdAt: serverTimestamp() };
    await addDoc(activityCol(uid), stored);
  } catch (e) {
    console.warn('Activity log failed:', e);
  }
};

// Dual-read during migration: merge the shared vault log (when unlocked) with the legacy
// per-device log, decrypt both, sort by time, and emit the latest `maxItems`. Old per-device
// entries simply age out; nothing is migrated.
export const listenToActivityLog = (uid, callback, maxItems = 30, cryptoKey = null) => {
  if (!uid) return () => {};

  let deviceEvents = [];
  let vaultEvents = [];
  let cancelled = false;
  const unsubs = [];

  const decryptDoc = async (d) => {
    const raw = d.data();
    if (cryptoKey && raw.iv && raw.data) {
      try {
        const dec = await decryptData(raw, cryptoKey);
        if (dec) return { id: d.id, ...dec, createdAt: raw.createdAt };
      } catch {
        /* fall through to raw */
      }
    }
    return { id: d.id, ...raw };
  };

  const emit = () => {
    if (cancelled) return;
    const merged = [...vaultEvents, ...deviceEvents].sort(
      (a, b) => tsMs(b.createdAt) - tsMs(a.createdAt),
    );
    callback(merged.slice(0, maxItems));
  };

  // Legacy per-device log.
  unsubs.push(
    onSnapshot(query(activityCol(uid), orderBy('createdAt', 'desc'), limit(maxItems)), async (snap) => {
      deviceEvents = await Promise.all(snap.docs.map(decryptDoc));
      emit();
    }),
  );

  // Shared vault log — needs the key to locate (vaultId) and decrypt.
  if (cryptoKey) {
    deriveVaultId(cryptoKey)
      .then((vaultId) => {
        if (cancelled) return;
        unsubs.push(
          onSnapshot(
            query(vaultActivityCol(vaultId), orderBy('createdAt', 'desc'), limit(maxItems)),
            async (snap) => {
              vaultEvents = await Promise.all(snap.docs.map(decryptDoc));
              emit();
            },
          ),
        );
      })
      .catch(() => {});
  }

  return () => {
    cancelled = true;
    unsubs.forEach((u) => u());
  };
};
