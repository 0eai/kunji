import { doc, getDoc, setDoc, deleteField } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  deriveKeyFromPasskey, deriveKeyArgon2id, generateSalt, generateMasterKey,
  exportKey, importMasterKey, encryptData, decryptData
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
    failedAttempts: deleteField(),
    lockoutUntil: deleteField(),
  }, { merge: true });
};
