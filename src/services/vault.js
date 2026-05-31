import { doc, getDoc, setDoc, deleteField } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  deriveKeyFromPasskey, deriveKeyArgon2id, generateSalt, generateMasterKey,
  exportKey, importMasterKey, encryptData, decryptData, getDefaultIterations,
  ARGON2_DEFAULTS, argon2ParamsFromDoc, argon2DocFields,
} from '../lib/crypto';

export const attemptVaultUnlock = async (userId, password) => {
  const userDocRef = doc(db, 'users', userId);
  const userDoc = await getDoc(userDocRef);
  const userData = userDoc.exists() ? userDoc.data() : {};

  let { encryptionSalt: salt, encryptedMasterKey: encryptedBlob } = userData;
  let masterKey;

  // New vault — initialize
  if (!salt || !encryptedBlob) {
    salt = generateSalt();
    masterKey = await generateMasterKey();
    const wrapperKey = await deriveKeyArgon2id(password, salt);
    const masterKeyJWK = await exportKey(masterKey);
    const encryptedMasterKey = await encryptData(masterKeyJWK, wrapperKey);
    const validationPayload = await encryptData({ check: 'VALID' }, masterKey);

    await setDoc(userDocRef, {
      encryptionSalt: salt,
      encryptedMasterKey,
      encryptedValidator: validationPayload,
      kdf: 'argon2id',
    }, { merge: true });

    return { status: 'success', masterKey, isNew: true };
  }

  // Existing vault — unlock
  try {
    const kdf = userData.kdf || 'pbkdf2';
    const wrapperKey = kdf === 'argon2id'
      ? await deriveKeyArgon2id(password, salt)
      : await deriveKeyFromPasskey(password, salt, userData.iterations);
    const masterKeyJWK = await decryptData(encryptedBlob, wrapperKey);

    if (!masterKeyJWK) throw new Error('WRONG_PASSWORD');

    masterKey = await importMasterKey(masterKeyJWK);

    if (userData.encryptedValidator) {
      const check = await decryptData(userData.encryptedValidator, masterKey);
      if (!check || check.check !== 'VALID') throw new Error('INTEGRITY_FAIL');
    }

    return { status: 'success', masterKey, isNew: false };
  } catch {
    throw new Error('WRONG_PASSWORD');
  }
};

export const resetUserVault = async (userId) => {
  const userDocRef = doc(db, 'users', userId);
  await setDoc(userDocRef, {
    encryptionSalt: deleteField(),
    encryptedMasterKey: deleteField(),
    encryptedValidator: deleteField(),
    kdf: deleteField(),
    iterations: deleteField(),
    argon2: deleteField(),
    failedAttempts: deleteField(),
    lockoutUntil: deleteField(),
  }, { merge: true });
};

/**
 * Provision this device's vault from a master key received via device-linking.
 * Wraps the (already-imported) master key with a new local passkey and writes the
 * vault doc, so this device unlocks independently while sharing the same identity.
 */
export const provisionVaultFromMasterKey = async (userId, masterKey, newPasskey) => {
  const masterKeyJWK = await exportKey(masterKey);
  const salt = generateSalt();
  const wrapperKey = await deriveKeyArgon2id(newPasskey, salt); // V2
  const encryptedMasterKey = await encryptData(masterKeyJWK, wrapperKey);
  const validationPayload = await encryptData({ check: 'VALID' }, masterKey);

  await setDoc(doc(db, 'users', userId), {
    encryptionSalt: salt,
    encryptedMasterKey,
    encryptedValidator: validationPayload,
    kdf: 'argon2id',
    argon2: argon2DocFields(ARGON2_DEFAULTS),
    failedAttempts: 0,
    lockoutUntil: 0,
  }, { merge: true });
};

/**
 * Generate a recovery key that can restore this vault on any device.
 * The master key is re-wrapped with an Argon2id key derived from a SEPARATE
 * recovery passphrase, so the recovery string is useless without that passphrase.
 * Output is the same `v2:` format the LockScreen recovery flow consumes.
 */
export const exportRecoveryKey = async (userId, passkey, recoveryPassphrase) => {
  const userDocRef = doc(db, 'users', userId);
  const userDoc = await getDoc(userDocRef);
  if (!userDoc.exists()) throw new Error('No vault found.');

  const data = userDoc.data();
  const { encryptionSalt, encryptedMasterKey, kdf, iterations } = data;

  const wrapperKey = kdf === 'argon2id'
    ? await deriveKeyArgon2id(passkey, encryptionSalt, argon2ParamsFromDoc(data))
    : await deriveKeyFromPasskey(passkey, encryptionSalt, iterations || getDefaultIterations());

  const masterKeyJWK = await decryptData(encryptedMasterKey, wrapperKey);
  if (!masterKeyJWK) throw new Error('Current passkey is incorrect.');

  // Re-wrap with an independent Argon2id key (V2) from the recovery passphrase.
  const recoverySalt = generateSalt();
  const recoveryWrapperKey = await deriveKeyArgon2id(recoveryPassphrase, recoverySalt); // V2
  const encryptedJWK = await encryptData(masterKeyJWK, recoveryWrapperKey);

  // v2 format: versioned prefix + base64(JSON({ salt, argon2, iv, data })).
  // The embedded `argon2` lets the recovery flow derive the same key on import.
  return 'v2:' + btoa(JSON.stringify({ salt: recoverySalt, argon2: argon2DocFields(ARGON2_DEFAULTS), ...encryptedJWK }));
};
