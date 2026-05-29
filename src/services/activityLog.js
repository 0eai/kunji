import {
  collection, addDoc, query, orderBy, limit, onSnapshot, serverTimestamp
} from 'firebase/firestore';
import { db } from '../lib/firebase';
import { encryptData, decryptData } from '../lib/crypto';

const activityCol = (uid) => collection(db, 'users', uid, 'activity_log');

export const logActivity = async (uid, action, type = 'success', icon = 'CheckCircle', cryptoKey = null) => {
  if (!uid) return;
  try {
    const payload = { action, type, icon };
    const stored = cryptoKey
      ? { ...(await encryptData(payload, cryptoKey)), createdAt: serverTimestamp() }
      : { action, type, icon, createdAt: serverTimestamp() };
    await addDoc(activityCol(uid), stored);
  } catch (e) {
    console.warn('Activity log failed:', e);
  }
};

export const listenToActivityLog = (uid, callback, maxItems = 30, cryptoKey = null) => {
  if (!uid) return () => {};
  const q = query(activityCol(uid), orderBy('createdAt', 'desc'), limit(maxItems));
  return onSnapshot(q, async (snap) => {
    const events = [];
    for (const d of snap.docs) {
      const raw = d.data();
      if (cryptoKey && raw.iv && raw.data) {
        try {
          const decrypted = await decryptData(raw, cryptoKey);
          if (decrypted) {
            events.push({ id: d.id, ...decrypted, createdAt: raw.createdAt });
            continue;
          }
        } catch { /* fall through */ }
      }
      events.push({ id: d.id, ...raw });
    }
    callback(events);
  });
};
