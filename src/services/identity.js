import {
  collection, doc, addDoc, getDoc, getDocs, deleteDoc,
  onSnapshot, orderBy, query, serverTimestamp
} from 'firebase/firestore';
import { ref, set, get } from 'firebase/database';
import { db, rtdb } from '../lib/firebase';
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

export const approveAuthSession = async (userId, cryptoKey, registeredAppId, sessionData, appName) => {
  const { sessionId, challenge } = sessionData;
  const secretKey = await getDecryptedPrivateKey(userId, cryptoKey, registeredAppId);

  const signedPayload = {
    sessionId,
    appId: registeredAppId,
    challenge,
    userId,
    timestamp: Date.now(),
  };
  const signedToken = signWithEd25519(signedPayload, secretKey);

  await set(ref(rtdb, `authSessions/${sessionId}`), {
    ...sessionData,
    status: 'approved',
    signedToken,
    signedPayload,
  });

  await logActivity(userId, `Approved login for ${appName}`, 'success', 'ShieldCheck', cryptoKey);
};

export const denyAuthSession = async (userId, sessionId, appName, cryptoKey) => {
  await set(ref(rtdb, `authSessions/${sessionId}/status`), 'denied');
  await logActivity(userId, `Denied login for ${appName}`, 'danger', 'ShieldX', cryptoKey);
};

export const parseQRPayload = (rawValue) => {
  let parsed;
  try {
    parsed = JSON.parse(rawValue);
  } catch {
    throw new Error('invalid_qr');
  }
  // Accept both kunjiAuth (v1) and sanctumAuth (v1) for backwards compatibility
  const isKunji = parsed?.kunjiAuth === 'v1';
  const isSanctum = parsed?.sanctumAuth === 'v1';
  if ((!isKunji && !isSanctum) || !parsed.sessionId || !parsed.registeredAppId || !parsed.challenge || !parsed.expiresAt) {
    throw new Error('invalid_qr');
  }
  if (Date.now() > parsed.expiresAt) {
    throw new Error('expired_qr');
  }
  return parsed;
};

export const fetchSessionFromRTDB = async (sessionId) => {
  const snap = await get(ref(rtdb, `authSessions/${sessionId}`));
  if (!snap.exists()) throw new Error('Session not found');
  return snap.val();
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
