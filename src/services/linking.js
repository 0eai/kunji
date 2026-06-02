// src/services/linking.js
// Device linking (issuer → consumer). The EXISTING, unlocked device (A) is the issuer:
// it shows a QR *and* a short numeric code. The NEW device (B) consumes either (scan or
// type). The vault master key travels A→B over an ECDH-encrypted channel relayed through
// kunji's own Firestore (linkSessions/) — the relay only ever holds ciphertext encrypted
// to a shared secret neither private key leaves.
//
// A releases the key only AFTER the user confirms a short shared-secret code (the SAS)
// shown identically on both screens. A substituted or guessed peer key produces a
// different shared secret → a different SAS → the user aborts before any key is sent.

import { doc, setDoc, updateDoc, getDoc, onSnapshot } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveECDHSharedSecret,
  deriveECDHSharedBits,
  encryptData,
  decryptData,
  exportKey,
  importMasterKey,
  generateSalt,
  deriveVaultId,
} from '../lib/crypto';

const LINK_TTL_MS = 2 * 60 * 1000; // 2 minutes
const LINK_LOOKUP_URL = import.meta.env.VITE_LINK_LOOKUP_URL || '/link/lookup';
const linkDoc = (linkId) => doc(db, 'linkSessions', linkId);

const eightDigitCode = () => {
  const v = window.crypto.getRandomValues(new Uint32Array(1))[0] % 100_000_000;
  return String(v).padStart(8, '0');
};

/**
 * A short, human-comparable fingerprint of a master key (first 6 hex of the
 * master-key-derived vaultId, grouped). Kept for the final "device linked" display.
 */
export const vaultFingerprint = async (masterKey) => {
  const id = await deriveVaultId(masterKey);
  const s = id.slice(0, 6).toUpperCase();
  return `${s.slice(0, 3)}-${s.slice(3)}`;
};

/**
 * The link SAS: a 6-digit code derived from the ECDH shared secret, identical on both
 * devices (each computes it from its own private key + the peer's public key). Compared
 * by the user BEFORE the master key is released; a substituted/guessed peer key yields a
 * different shared secret → a different SAS → mismatch.
 */
export const deriveLinkSas = async (privateKey, peerPublicKey) => {
  const bits = await deriveECDHSharedBits(privateKey, peerPublicKey);
  const label = new TextEncoder().encode('kunji-link-sas-v1');
  const material = new Uint8Array(bits.byteLength + label.byteLength);
  material.set(new Uint8Array(bits), 0);
  material.set(label, bits.byteLength);
  const digest = await window.crypto.subtle.digest('SHA-256', material);
  const n = new DataView(digest).getUint32(0) % 1_000_000;
  const s = String(n).padStart(6, '0');
  return `${s.slice(0, 3)}-${s.slice(3)}`;
};

// ===== Existing device (A) — issuer =====

/**
 * Device A (unlocked). Create a link session, publishing A's ephemeral public key and a
 * short lookup code. Returns the QR payload, the code to display, the private key A must
 * hold while waiting, and the linkId.
 */
export const startLinkAsIssuer = async () => {
  const keyPair = await generateECDHKeyPair();
  const pubA = await exportECDHPublicKey(keyPair.publicKey);
  const linkId = generateSalt() + generateSalt(); // 256-bit secret doc id
  const code = eightDigitCode();
  const expiresAt = Date.now() + LINK_TTL_MS;

  await setDoc(linkDoc(linkId), {
    pubA,
    code,
    status: 'pending',
    expiresAt,
    ttl: new Date(expiresAt + 5 * 60 * 1000), // add a Firestore TTL policy on `ttl` to auto-clean
  });

  const qrData = JSON.stringify({ kunjiLink: 'v2', linkId, pubA });
  return { linkId, code, privateKey: keyPair.privateKey, qrData };
};

/**
 * Device A. Listen for the new device to publish its key (pending → keyset). Computes the
 * SAS and hands it back via onPeer(sas, pubB) WITHOUT depositing — the deposit waits for
 * the user to confirm the SAS. Returns an unsubscribe function.
 */
export const watchForPeerKey = (linkId, privateKeyA, onPeer, onError) => {
  return onSnapshot(linkDoc(linkId), async (snap) => {
    const data = snap.data();
    if (!data || data.status !== 'keyset' || !data.pubB) return;
    try {
      const pubB = await importECDHPublicKey(data.pubB);
      const sas = await deriveLinkSas(privateKeyA, pubB);
      onPeer(sas, data.pubB);
    } catch (e) {
      onError?.(e);
    }
  });
};

/**
 * Device A, after the user confirms the SAS matches: encrypt the master key to the shared
 * secret and deposit it (keyset → sent). Kunji's master key never leaves in plaintext.
 */
export const depositMasterKey = async (linkId, privateKeyA, masterKey, pubBBase64) => {
  const pubB = await importECDHPublicKey(pubBBase64);
  const shared = await deriveECDHSharedSecret(privateKeyA, pubB);
  const masterKeyJWK = await exportKey(masterKey);
  const encryptedMasterKey = await encryptData(masterKeyJWK, shared);
  await updateDoc(linkDoc(linkId), { encryptedMasterKey, status: 'sent' });
};

// ===== New device (B) — consumer =====

/** Parse an issuer QR ({kunjiLink:'v2', linkId, pubA}). */
export const parseLinkQR = (raw) => {
  let qr;
  try {
    qr = JSON.parse(raw);
  } catch {
    throw new Error('invalid_link_qr');
  }
  if (qr?.kunjiLink !== 'v2' || !qr.linkId || !qr.pubA) throw new Error('invalid_link_qr');
  return { linkId: qr.linkId, pubA: qr.pubA };
};

/** Resolve a typed link code to {linkId, pubA} via the rate-limited lookup Function. */
export const resolveLinkCode = async (code) => {
  const resp = await fetch(`${LINK_LOOKUP_URL}?code=${encodeURIComponent(code)}`);
  if (resp.status === 404) throw new Error('invalid_code');
  if (resp.status === 410) throw new Error('expired_code');
  if (resp.status === 429) throw new Error('rate_limited');
  if (!resp.ok) throw new Error('lookup_failed');
  const s = await resp.json();
  if (!s.linkId || !s.pubA) throw new Error('lookup_failed');
  return { linkId: s.linkId, pubA: s.pubA };
};

/**
 * Device B. Publish B's ephemeral public key (pending → keyset) and return what B needs
 * to show the SAS and later decrypt the deposited master key.
 */
export const submitPeerKey = async (linkId, pubABase64) => {
  const snap = await getDoc(linkDoc(linkId));
  if (!snap.exists()) throw new Error('link_not_found');
  const session = snap.data();
  if (session.status !== 'pending') throw new Error('link_already_used');
  if (Date.now() > session.expiresAt) throw new Error('link_expired');

  const keyPair = await generateECDHKeyPair();
  const pubB = await exportECDHPublicKey(keyPair.publicKey);
  const pubA = await importECDHPublicKey(pubABase64);
  const sas = await deriveLinkSas(keyPair.privateKey, pubA);

  await updateDoc(linkDoc(linkId), { pubB, status: 'keyset' });
  return { privateKey: keyPair.privateKey, pubA: pubABase64, sas };
};

/**
 * Device B. Listen for device A to deposit the encrypted master key (keyset → sent), then
 * decrypt it. Calls onReceived(masterKey: CryptoKey) once. Returns an unsubscribe function.
 */
export const watchForLinkedKey = (linkId, privateKeyB, pubABase64, onReceived, onError) => {
  return onSnapshot(linkDoc(linkId), async (snap) => {
    const data = snap.data();
    if (!data || data.status !== 'sent' || !data.encryptedMasterKey) return;
    try {
      const pubA = await importECDHPublicKey(pubABase64);
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
