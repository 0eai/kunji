import { doc, getDoc } from 'firebase/firestore';
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

/** Load the custom profile, or null if none set. Returns { displayName, avatar }. */
export const loadProfile = async (vaultId, cryptoKey) => {
  try {
    const snap = await getDoc(profileRef(vaultId));
    if (!snap.exists()) return null;
    const dec = await decryptData(snap.data(), cryptoKey);
    if (!dec) return null;
    return { displayName: dec.displayName || '', avatar: dec.avatar || '' };
  } catch {
    return null;
  }
};

/** Save (or clear) the custom profile. `avatar` is a small data-URI or ''. */
export const saveProfile = async (vaultId, cryptoKey, { displayName = '', avatar = '' }, userId) => {
  const clean = { displayName: String(displayName).slice(0, 60).trim(), avatar: avatar || '' };
  if (!clean.displayName && !clean.avatar) {
    await writeProfile(vaultId, cryptoKey, 'delete', null);
  } else {
    const payload = await encryptData(clean, cryptoKey);
    await writeProfile(vaultId, cryptoKey, 'set', payload);
  }
  if (userId) await logActivity(userId, 'Updated profile', 'info', 'CheckCircle', cryptoKey);
  return clean;
};
