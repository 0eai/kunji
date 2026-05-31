// src/services/linking.js
// QR device-linking: securely carry the vault master key from an unlocked device (A)
// to a new device (B) over an ECDH-encrypted channel relayed through kunji's own
// Firestore (linkSessions/). The relay only ever holds ciphertext encrypted to B's
// ephemeral key, which never leaves B — same trust model as WhatsApp Web.

import { doc, setDoc, updateDoc, getDoc, onSnapshot } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  generateECDHKeyPair, exportECDHPublicKey, importECDHPublicKey, deriveECDHSharedSecret,
  encryptData, decryptData, exportKey, importMasterKey, generateSalt, deriveVaultId,
} from '../lib/crypto';

const LINK_TTL_MS = 5 * 60 * 1000; // 5 minutes
const linkDoc = (linkId) => doc(db, 'linkSessions', linkId);

/**
 * A short, human-comparable fingerprint of a master key (first 6 hex of the
 * master-key-derived vaultId, grouped). Both devices compute it from the same key;
 * if a linked key was substituted in transit, the two fingerprints won't match.
 */
export const vaultFingerprint = async (masterKey) => {
  const id = await deriveVaultId(masterKey);
  const s = id.slice(0, 6).toUpperCase();
  return `${s.slice(0, 3)}-${s.slice(3)}`;
};

/**
 * Device B (new device). Creates a link session and returns its QR payload plus the
 * ephemeral private key the caller must hold while waiting for the transfer.
 */
export const startLink = async () => {
  const keyPair = await generateECDHKeyPair();
  const pubB = await exportECDHPublicKey(keyPair.publicKey);
  const linkId = generateSalt() + generateSalt(); // 32-byte random secret id

  await setDoc(linkDoc(linkId), {
    pubB,
    status: 'pending',
    expiresAt: Date.now() + LINK_TTL_MS,
  });

  const qrData = JSON.stringify({ kunjiLink: 'v1', linkId, pubB });
  return { linkId, privateKey: keyPair.privateKey, qrData };
};

/**
 * Device B. Listen for device A to deposit the encrypted master key, then decrypt it.
 * Calls onReceived(masterKey: CryptoKey) once. Returns an unsubscribe function.
 */
export const listenForLinkedKey = (linkId, privateKeyB, onReceived, onError) => {
  return onSnapshot(linkDoc(linkId), async (snap) => {
    const data = snap.data();
    if (!data || data.status !== 'sent' || !data.pubA || !data.encryptedMasterKey) return;
    try {
      const pubA = await importECDHPublicKey(data.pubA);
      const shared = await deriveECDHSharedSecret(privateKeyB, pubA);
      const masterKeyJWK = await decryptData(data.encryptedMasterKey, shared);
      if (!masterKeyJWK) throw new Error('decrypt_failed');
      const masterKey = await importMasterKey(masterKeyJWK);
      onReceived(masterKey);
    } catch (e) {
      onError?.(e);
    }
  });
};

/**
 * Device A (unlocked). Scan B's QR, encrypt the master key to B's ephemeral key,
 * and deposit it in the relay. Kunji's master key never leaves in plaintext.
 */
export const completeLink = async (scannedQrRaw, masterKey) => {
  let qr;
  try {
    qr = JSON.parse(scannedQrRaw);
  } catch {
    throw new Error('invalid_link_qr');
  }
  if (qr?.kunjiLink !== 'v1' || !qr.linkId || !qr.pubB) throw new Error('invalid_link_qr');

  // The session must still be open.
  const snap = await getDoc(linkDoc(qr.linkId));
  if (!snap.exists()) throw new Error('link_not_found');
  const session = snap.data();
  if (session.status !== 'pending') throw new Error('link_already_used');
  if (Date.now() > session.expiresAt) throw new Error('link_expired');

  const keyPair = await generateECDHKeyPair();
  const pubA = await exportECDHPublicKey(keyPair.publicKey);
  const pubB = await importECDHPublicKey(qr.pubB);
  const shared = await deriveECDHSharedSecret(keyPair.privateKey, pubB);

  const masterKeyJWK = await exportKey(masterKey);
  const encryptedMasterKey = await encryptData(masterKeyJWK, shared);

  await updateDoc(linkDoc(qr.linkId), { pubA, encryptedMasterKey, status: 'sent' });
};
