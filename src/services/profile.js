import { doc, onSnapshot } from 'firebase/firestore';
import { db } from '../lib/firebase';
import { encryptData, decryptData } from '../lib/crypto';
import {
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../lib/crypto';
import { logActivity } from './activityLog';

// The user's OPTIONAL custom profile (Layer 2). Stored encrypted under the vault so it
// syncs across linked devices; shared with an app only on explicit per-login consent.
// kunji's default identity (Layer 1, see lib/kunjiHandle) needs none of this.
const VAULT_WRITE_URL = import.meta.env.VITE_VAULT_WRITE_URL || '/vault/write';
const profileRef = (vaultId) => doc(db, 'vaults', vaultId, 'profile', 'self');

// Signed profile write — same model as identity.js's app writes, but with kind:'profile'
// so the Cloud Function routes it to vaults/{vaultId}/profile/self. The function never
// sees the master key or plaintext — only the encrypted blob + a vault-write signature.
const writeProfile = async (vaultId, cryptoKey, op, docPayload) => {
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const timestamp = Date.now();
  const signed = {
    appId: 'self',
    doc: docPayload ?? null,
    kind: 'profile',
    op,
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
      op,
      appId: 'self',
      kind: 'profile',
      doc: docPayload ?? undefined,
      publicKey: publicKeyB64,
      signedToken,
      timestamp,
    }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('profile_write_failed:' + (e.error || resp.status));
  }
};

// Decrypt one profile snapshot → { displayName, avatar, shareByDefault } | null (no doc / undecryptable).
const decodeProfile = async (snap, cryptoKey) => {
  if (!snap.exists()) return null;
  try {
    const dec = await decryptData(snap.data(), cryptoKey);
    if (!dec) return null;
    return {
      displayName: dec.displayName || '',
      avatar: dec.avatar || '',
      shareByDefault: !!dec.shareByDefault,
    };
  } catch {
    return null;
  }
};

/**
 * Live custom-profile listener — mirrors `listenToApps` (services/identity.js). Invokes
 * `cb(profile | null)` with the current value and on every change. Because it's an onSnapshot (not a
 * one-shot read), the optional profile syncs across linked devices the same way the apps list does,
 * and a transient read miss self-heals when the listener reconnects (the old one-shot getDoc did
 * neither — it fired once and silently returned null on any hiccup). Returns an unsubscribe fn.
 */
export const watchProfile = (vaultId, cryptoKey, cb) =>
  onSnapshot(profileRef(vaultId), async (snap) => {
    cb(await decodeProfile(snap, cryptoKey));
  });

/**
 * Save (or clear) the custom profile. `avatar` is a small data-URI or ''. `shareByDefault` makes the
 * approval dialog's "Share your profile" toggle start ON (still per-app, still user-overridable); it
 * only rides along when there's content — no name/avatar ⇒ the doc is deleted and the flag is moot.
 */
export const saveProfile = async (
  vaultId,
  cryptoKey,
  { displayName = '', avatar = '', shareByDefault = false },
  userId,
) => {
  const clean = {
    displayName: String(displayName).slice(0, 60).trim(),
    avatar: avatar || '',
    shareByDefault: !!shareByDefault,
  };
  if (!clean.displayName && !clean.avatar) {
    await writeProfile(vaultId, cryptoKey, 'delete', null);
  } else {
    const payload = await encryptData(clean, cryptoKey);
    await writeProfile(vaultId, cryptoKey, 'set', payload);
  }
  if (userId) await logActivity(userId, 'Updated profile', 'info', 'CheckCircle', cryptoKey);
  return clean;
};
