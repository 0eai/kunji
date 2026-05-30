import {
  collection, doc, addDoc, getDocs, deleteDoc, setDoc,
  onSnapshot, orderBy, query, serverTimestamp
} from 'firebase/firestore';
import { db } from '../lib/firebase';
import { encryptData, decryptData } from '../lib/crypto';
import {
  deriveAppKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../lib/crypto';
import { logActivity } from './activityLog';

// Apps are keyed by the master-key-derived vaultId so the list syncs across every
// linked device. Activity logging stays per-device (userId).
const appsCol = (vaultId) => collection(db, 'vaults', vaultId, 'apps');
const appDoc = (vaultId, appId) => doc(db, 'vaults', vaultId, 'apps', appId);

export const listenToApps = (vaultId, cryptoKey, callback) => {
  const q = query(appsCol(vaultId), orderBy('createdAt', 'asc'));
  return onSnapshot(q, async (snap) => {
    const apps = [];
    for (const d of snap.docs) {
      const raw = d.data();
      try {
        const decrypted = await decryptData(raw, cryptoKey);
        if (decrypted) {
          apps.push({ id: d.id, ...decrypted, publicKey: raw.publicKey, createdAt: raw.createdAt });
        }
      } catch {
        // Skip corrupted docs silently
      }
    }
    callback(apps);
  });
};

export const registerApp = async (vaultId, cryptoKey, { name, domain, iconUrl = '' }, userId) => {
  // Per-app keypair is derived from the master key + domain (not stored).
  const { publicKey } = await deriveAppKeyPair(cryptoKey, domain);
  const pubKeyBase64 = exportEd25519PublicKey(publicKey);

  // Only display metadata is persisted (encrypted at rest); the signing key is
  // reproduced on demand from the master key, so it never needs to be stored.
  const payload = await encryptData({ name, domain, iconUrl }, cryptoKey);

  const docRef = await addDoc(appsCol(vaultId), {
    ...payload,
    publicKey: pubKeyBase64,
    createdAt: serverTimestamp(),
  });

  if (userId) await logActivity(userId, `Registered app: ${name}`, 'success', 'Link', cryptoKey);
  return { registeredAppId: docRef.id, publicKey: pubKeyBase64 };
};

export const deleteApp = async (vaultId, registeredAppId, appName, cryptoKey, userId) => {
  await deleteDoc(appDoc(vaultId, registeredAppId));
  if (userId) await logActivity(userId, `Removed app: ${appName}`, 'info', 'Unlink', cryptoKey);
};

/**
 * One-time migration: copy apps from the legacy per-device path (users/{uid}/apps)
 * to the shared vault path (vaults/{vaultId}/apps) so previously-registered apps
 * reappear after the move to vaultId-keyed storage. Idempotent (same doc ids).
 */
export const migrateLegacyApps = async (userId, vaultId) => {
  const legacy = await getDocs(collection(db, 'users', userId, 'apps'));
  if (legacy.empty) return 0;
  let n = 0;
  for (const d of legacy.docs) {
    await setDoc(appDoc(vaultId, d.id), d.data());
    n++;
  }
  return n;
};

/**
 * Derive the stable per-app subject ID from the app's Ed25519 public key.
 * `sub = hex( SHA-256( utf8(publicKeyBase64) ) )`. Self-contained: the relying
 * party recomputes the same value from the public key it receives (no kunji UID
 * involved). Stable per (user, app) — the keypair is per app domain — and
 * different across apps, so apps cannot correlate the same kunji user.
 */
export const deriveSubFromPublicKey = async (publicKeyBase64) => {
  const data = new TextEncoder().encode(publicKeyBase64);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * Parse a v2 discoverable-login QR payload.
 * Shape: { kunjiAuth:'v2', mode:'discoverable', sessionId, challenge, audience,
 *          callbackUrl, appName?, iconUrl?, expiresAt }
 * The callbackUrl must be same-site as the audience and HTTPS (localhost may use HTTP).
 */
export const parseQRPayload = (rawValue) => {
  let parsed;
  try {
    parsed = JSON.parse(rawValue);
  } catch {
    throw new Error('invalid_qr');
  }

  if (
    parsed?.kunjiAuth !== 'v2' ||
    parsed.mode !== 'discoverable' ||
    !parsed.sessionId || !parsed.challenge || !parsed.audience ||
    !parsed.callbackUrl || !parsed.expiresAt
  ) {
    throw new Error('invalid_qr');
  }

  // Callback must be same-site as the audience the user is shown, over HTTPS
  // (HTTP allowed only for localhost so the local demo works).
  let cbUrl;
  try {
    cbUrl = new URL(parsed.callbackUrl);
  } catch {
    throw new Error('untrusted_callback');
  }
  const host = cbUrl.hostname;
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  const sameSite = host === parsed.audience || host.endsWith('.' + parsed.audience);
  const secure = cbUrl.protocol === 'https:' || (isLocal && cbUrl.protocol === 'http:');
  if (!sameSite || !secure) {
    throw new Error('untrusted_callback');
  }

  if (Date.now() > parsed.expiresAt) {
    throw new Error('expired_qr');
  }

  return parsed;
};

/**
 * Sign the discoverable-login assertion with the app's per-app key and POST it
 * to the relying party's callback URL. Kunji writes nothing to any shared store —
 * the only outbound effect is this single HTTPS POST to the app's own endpoint.
 */
export const submitDiscoverableAssertion = async (userId, cryptoKey, qr) => {
  // Reproduce the per-app keypair from the master key + audience domain.
  const { secretKey, publicKey } = await deriveAppKeyPair(cryptoKey, qr.audience);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const sub = await deriveSubFromPublicKey(publicKeyB64);

  const signedPayload = {
    sessionId: qr.sessionId,
    challenge: qr.challenge,
    audience: qr.audience,
    sub,
    timestamp: Date.now(),
  };
  const signedToken = signWithEd25519(signedPayload, secretKey);

  const resp = await fetch(qr.callbackUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: publicKeyB64, signedPayload, signedToken }),
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(`callback_rejected:${resp.status}${detail ? ` ${detail}` : ''}`);
  }

  await logActivity(userId, `Signed in to ${qr.audience}`, 'success', 'ShieldCheck', cryptoKey);
  return { sub };
};

export const exportAllApps = async (vaultId, cryptoKey) => {
  const snap = await getDocs(appsCol(vaultId));
  const apps = [];
  for (const d of snap.docs) {
    const raw = d.data();
    try {
      const dec = await decryptData(raw, cryptoKey);
      if (dec) apps.push({ id: d.id, name: dec.name, domain: dec.domain, iconUrl: dec.iconUrl, publicKey: raw.publicKey });
    } catch { /* skip */ }
  }
  return apps;
};
