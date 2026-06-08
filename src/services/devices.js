// Linked-devices registry (Layer-2, vault-scoped, encrypted). A small record per device that holds
// this identity — so the user can SEE which devices are linked. Awareness-only: there is no remote
// "unlink" (that would require rotating the master key, which re-derives vaultId and re-keys every
// app); to remove a device, sign out on that device. Mirrors services/capability.js's signed write.
import { collection, getDocs } from 'firebase/firestore';
import { db } from '../lib/firebase';
import {
  deriveVaultId,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
  encryptData,
  decryptData,
} from '../lib/crypto';
import { deviceLabel } from '../lib/deviceInfo';

const VAULT_WRITE_URL = import.meta.env.VITE_VAULT_WRITE_URL || '/vault/write';
const ID_KEY = 'kunji_device_id'; // stable per device/browser
const RECORDED_KEY = 'kunji_device_recorded'; // skip the write once this device is registered

// A stable id for THIS device/browser (random; SAFE_ID-valid hex+dashes). Survives lock/unlock.
export const thisDeviceId = () => {
  let id = null;
  try {
    id = localStorage.getItem(ID_KEY);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(ID_KEY, id);
    }
  } catch {
    id = id || crypto.randomUUID(); // private-mode / no storage → ephemeral id
  }
  return id;
};

// Signed write of one encrypted device record (vaultWrite kind:'device'). Mirrors agentVaultWrite.
const writeDevice = async (cryptoKey, deviceId, docPayload) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(cryptoKey);
  const publicKeyB64 = exportEd25519PublicKey(publicKey);
  const timestamp = Date.now();
  const signed = {
    appId: deviceId,
    doc: docPayload,
    kind: 'device',
    op: 'set',
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
      op: 'set',
      appId: deviceId,
      kind: 'device',
      doc: docPayload,
      publicKey: publicKeyB64,
      signedToken,
      timestamp,
    }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('device_write_failed:' + (e.error || resp.status));
  }
};

/** Register THIS device in the shared list (once per device). Best-effort; never blocks unlock. */
export const recordThisDevice = async (cryptoKey) => {
  const id = thisDeviceId();
  try {
    if (localStorage.getItem(RECORDED_KEY) === id) return; // already recorded this device
  } catch {
    /* no storage — fall through and (re)write */
  }
  const payload = await encryptData(
    { label: deviceLabel(), createdAt: Math.floor(Date.now() / 1000) },
    cryptoKey,
  );
  await writeDevice(cryptoKey, id, payload);
  try {
    localStorage.setItem(RECORDED_KEY, id);
  } catch {
    /* best-effort */
  }
};

/** The devices linked to this identity, decrypted, newest first. `{ id, label, createdAt }[]`. */
export const listDevices = async (cryptoKey) => {
  const vaultId = await deriveVaultId(cryptoKey);
  const snap = await getDocs(collection(db, 'vaults', vaultId, 'devices'));
  const devices = [];
  for (const d of snap.docs) {
    const dec = await decryptData(d.data(), cryptoKey);
    if (dec) devices.push({ id: d.id, label: dec.label || 'Unknown device', createdAt: dec.createdAt });
  }
  return devices.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
};
