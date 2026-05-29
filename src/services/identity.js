import {
  collection, doc, addDoc, getDoc, getDocs, deleteDoc,
  onSnapshot, orderBy, query, serverTimestamp
} from 'firebase/firestore';
import { db } from '../lib/firebase';
import { encryptData, decryptData } from '../lib/crypto';
import {
  generateEd25519KeyPair,
  exportEd25519SecretKey,
  exportEd25519PublicKey,
  importEd25519SecretKey,
  signWithEd25519,
} from '../lib/crypto';
import { logActivity } from './activityLog';

const appsCol = (userId) => collection(db, 'users', userId, 'apps');
const appDoc = (userId, appId) => doc(db, 'users', userId, 'apps', appId);

export const listenToApps = (userId, cryptoKey, callback) => {
  const q = query(appsCol(userId), orderBy('createdAt', 'asc'));
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

export const registerApp = async (userId, cryptoKey, { name, domain, iconUrl = '' }) => {
  const { secretKey, publicKey } = generateEd25519KeyPair();
  const privKeyBase64 = exportEd25519SecretKey(secretKey);
  const pubKeyBase64 = exportEd25519PublicKey(publicKey);

  const encryptedPrivateKey = await encryptData({ key: privKeyBase64 }, cryptoKey);
  const payload = await encryptData({ name, domain, iconUrl, encryptedPrivateKey }, cryptoKey);

  const docRef = await addDoc(appsCol(userId), {
    ...payload,
    publicKey: pubKeyBase64,
    createdAt: serverTimestamp(),
  });

  await logActivity(userId, `Registered app: ${name}`, 'success', 'Link', cryptoKey);
  return { registeredAppId: docRef.id, publicKey: pubKeyBase64 };
};

export const deleteApp = async (userId, registeredAppId, appName, cryptoKey) => {
  await deleteDoc(appDoc(userId, registeredAppId));
  await logActivity(userId, `Removed app: ${appName}`, 'info', 'Unlink', cryptoKey);
};

const getDecryptedPrivateKey = async (userId, cryptoKey, registeredAppId) => {
  const snap = await getDoc(appDoc(userId, registeredAppId));
  if (!snap.exists()) throw new Error('App not found');
  const raw = snap.data();
  const decrypted = await decryptData(raw, cryptoKey);
  const privKeyData = await decryptData(decrypted.encryptedPrivateKey, cryptoKey);
  return importEd25519SecretKey(privKeyData.key);
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
export const submitDiscoverableAssertion = async (userId, cryptoKey, app, qr) => {
  const secretKey = await getDecryptedPrivateKey(userId, cryptoKey, app.registeredAppId);
  const publicKey = app.publicKey;
  const sub = await deriveSubFromPublicKey(publicKey);

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
    body: JSON.stringify({ publicKey, signedPayload, signedToken }),
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(`callback_rejected:${resp.status}${detail ? ` ${detail}` : ''}`);
  }

  await logActivity(userId, `Signed in to ${qr.audience}`, 'success', 'ShieldCheck', cryptoKey);
  return { sub };
};

export const exportAllApps = async (userId, cryptoKey) => {
  const snap = await getDocs(appsCol(userId));
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
