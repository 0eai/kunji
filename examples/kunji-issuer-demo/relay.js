// Issuer-side relay deposit (async issuance): ECDH-encrypt the SD-JWT to the wallet's transport key
// — matching src/lib/crypto encryptData byte-for-byte — and POST it to the kunji credential relay,
// where the wallet polls /credential/poll and decrypts. The relay only ever holds ciphertext + the
// issuer's ephemeral pub. See ../../docs/verified-credentials.md.
import { randomBytes } from 'node:crypto';

const subtle = globalThis.crypto.subtle;
const genECDH = () => subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
const exportSpkiB64 = async (pub) => Buffer.from(await subtle.exportKey('spki', pub)).toString('base64');
const importSpki = (b64) =>
  subtle.importKey('spki', Buffer.from(b64, 'base64'), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
const deriveAesKey = (priv, pub) =>
  subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

// Mirror src/lib/crypto encryptData: JSON.stringify(value) → AES-GCM(12-byte iv) → {iv,data} std base64.
const encryptData = async (value, key) => {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(value)));
  return { iv: Buffer.from(iv).toString('base64'), data: Buffer.from(ct).toString('base64') };
};

// Where the wallet polls. Override for local/staging (e.g. KUNJI_RELAY_URL=http://localhost:5005).
const RELAY_URL = (process.env.KUNJI_RELAY_URL || 'https://app.kunji.cc').replace(/\/$/, '');

/** ECDH-encrypt `sdjwt` to the wallet's `transportPub` and deposit it for the wallet to poll. */
export const depositToRelay = async ({ sdjwt, transportPub, sessionId, issuer }) => {
  const eph = await genECDH();
  const issuerPubE = await exportSpkiB64(eph.publicKey);
  const shared = await deriveAesKey(eph.privateKey, await importSpki(transportPub));
  const encryptedCredential = await encryptData(sdjwt, shared);
  const resp = await fetch(`${RELAY_URL}/credential/offer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, issuerPubE, encryptedCredential, issuer }),
  });
  if (!resp.ok) throw new Error('relay_deposit_failed:' + resp.status);
};
