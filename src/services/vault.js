import { doc, getDoc, setDoc, deleteField } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  deriveKeyFromPasskey,
  deriveKeyArgon2id,
  generateSalt,
  exportKey,
  encryptData,
  decryptData,
  getDefaultIterations,
  ARGON2_DEFAULTS,
  argon2ParamsFromDoc,
  argon2DocFields,
} from '../lib/crypto';

export const resetUserVault = async (userId) => {
  const userDocRef = doc(db, 'users', userId);
  await setDoc(
    userDocRef,
    {
      encryptionSalt: deleteField(),
      encryptedMasterKey: deleteField(),
      encryptedValidator: deleteField(),
      kdf: deleteField(),
      iterations: deleteField(),
      argon2: deleteField(),
      failedAttempts: deleteField(),
      lockoutUntil: deleteField(),
    },
    { merge: true },
  );
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

  await setDoc(
    doc(db, 'users', userId),
    {
      encryptionSalt: salt,
      encryptedMasterKey,
      encryptedValidator: validationPayload,
      kdf: 'argon2id',
      argon2: argon2DocFields(ARGON2_DEFAULTS),
      failedAttempts: 0,
      lockoutUntil: 0,
    },
    { merge: true },
  );
};

/**
 * Change this device's vault passkey. Requires the CURRENT passkey (re-auth: verifies it
 * by re-deriving the existing wrap and decrypting), then re-wraps the already-unlocked
 * master key under the NEW passkey with fresh V2 (Argon2id) params. The master key — and
 * therefore the vaultId and every connected app — is unchanged; only the local wrap
 * changes, so other linked devices keep their own passkeys.
 */
export const changePasskey = async (userId, masterKey, currentPasskey, newPasskey) => {
  const userDocRef = doc(db, 'users', userId);
  const userDoc = await getDoc(userDocRef);
  if (!userDoc.exists()) throw new Error('No vault found.');

  const data = userDoc.data();
  const { encryptionSalt, encryptedMasterKey, kdf, iterations } = data;

  // Verify the current passkey by re-deriving its wrapper and decrypting the blob.
  const wrapperKey =
    kdf === 'argon2id'
      ? await deriveKeyArgon2id(currentPasskey, encryptionSalt, argon2ParamsFromDoc(data))
      : await deriveKeyFromPasskey(currentPasskey, encryptionSalt, iterations || getDefaultIterations());
  const ok = await decryptData(encryptedMasterKey, wrapperKey);
  if (!ok) throw new Error('Current passkey is incorrect.');

  // Re-wrap the in-memory master key under the new passkey (same path as device-link
  // provisioning: fresh salt + V2 Argon2id params + reset lockout counters).
  await provisionVaultFromMasterKey(userId, masterKey, newPasskey);
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

  const wrapperKey =
    kdf === 'argon2id'
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
  return (
    'v2:' +
    btoa(
      JSON.stringify({
        salt: recoverySalt,
        argon2: argon2DocFields(ARGON2_DEFAULTS),
        ...encryptedJWK,
      }),
    )
  );
};
