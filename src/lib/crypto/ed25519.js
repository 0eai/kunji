// lib/crypto/ed25519.js — Ed25519 signing for Connected Apps passwordless auth

import { ed25519 } from '@noble/curves/ed25519.js';
import { bufferToBase64, base64ToBuffer, normalizeDomain } from './helpers';

export const generateEd25519KeyPair = () => {
  const { secretKey, publicKey } = ed25519.keygen();
  return { secretKey, publicKey };
};

// Deterministically derive a per-app Ed25519 keypair from the vault master key + app domain.
// seed = HKDF-SHA256(rawMasterKey, info="kunji-app:"+domain). The same (masterKey, domain)
// always yields the same keypair, so any device holding the master key reproduces every
// app's identity — no keypair data needs to sync between devices.
export const deriveAppKeyPair = async (masterKey, domain) => {
  // Normalize the domain so casing/trailing-dot/default-port variants map to one identity.
  const normalized = normalizeDomain(domain);
  const raw = await window.crypto.subtle.exportKey('raw', masterKey);
  const ikm = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('kunji-app-key-v1'),
      info: new TextEncoder().encode(`kunji-app:${normalized}`),
    },
    ikm,
    256,
  );
  const secretKey = new Uint8Array(bits);
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
};

// Deterministically derive the per-vault WRITE keypair from the master key. The
// public key is registered (trust-on-first-use) with the vault-write Cloud Function;
// every vault write is signed with the secret key, so possession of the master key —
// not just knowledge of the vaultId — is required to write. info is domain-separated
// from per-app keys and the vaultId.
export const deriveVaultWriteKeyPair = async (masterKey) => {
  const raw = await window.crypto.subtle.exportKey('raw', masterKey);
  const ikm = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('kunji-vault-write-v1'),
      info: new TextEncoder().encode('kunji-vault-write'),
    },
    ikm,
    256,
  );
  const secretKey = new Uint8Array(bits);
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
};

// Deterministically derive a per-ISSUER credential holder keypair from the master key. A verified
// credential binds to this key (`cnf`); the holder proves possession at presentation via a
// Key-Binding JWT. Per-issuer (the issuer is in `info`) bounds the cross-RP correlation surface.
// Domain-separated from per-app keys, the vault-write key, and the vaultId. See
// docs/verified-credentials.md §5.
export const deriveCredentialHolderKey = async (masterKey, issuer) => {
  const raw = await window.crypto.subtle.exportKey('raw', masterKey);
  const ikm = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('kunji-cred-holder-v1'),
      info: new TextEncoder().encode(`kunji-cred-holder:${String(issuer)}`),
    },
    ikm,
    256,
  );
  const secretKey = new Uint8Array(bits);
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
};

// Deterministically derive a per-app OPAQUE channel id (not a keypair) from the master key — the push
// relay's mailbox address (push-relay.md §3). Per-audience + domain-separated, so it's unlinkable across
// apps and kunji learns nothing about who/what the channel is. 256-bit → 64-hex. Additive; the existing
// byte-stable derivations are untouched.
export const deriveChannelId = async (masterKey, audience) => {
  const normalized = normalizeDomain(audience);
  const raw = await window.crypto.subtle.exportKey('raw', masterKey);
  const ikm = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('kunji-channel-v1'),
      info: new TextEncoder().encode(`kunji-channel:${normalized}`),
    },
    ikm,
    256,
  );
  return Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

// Deterministically derive a per-ISSUER BBS holder secret (32 bytes) from the master key. A
// holder-bound BBS credential (verified-credentials.md §7 v3) signs this as an always-undisclosed
// message; the holder re-derives it to present (BBS proof generation needs every message value), so a
// leaked credential blob without the master key can't be presented — non-transferability. Never stored
// in the blob. Per-issuer + domain-separated from the app/vault/cred-holder/channel derivations. Additive.
export const deriveBbsHolderSecret = async (masterKey, issuer) => {
  // Raw issuer origin (matches deriveCredentialHolderKey) — `iss` is a full origin the wallet passes
  // canonically at both receive and present, so no normalization is needed (or correct on a URL).
  const raw = await window.crypto.subtle.exportKey('raw', masterKey);
  const ikm = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('kunji-bbs-holder-v1'),
      info: new TextEncoder().encode(`kunji-bbs-holder:${String(issuer)}`),
    },
    ikm,
    256,
  );
  return new Uint8Array(bits);
};

export const exportEd25519SecretKey = (secretKey) => bufferToBase64(secretKey.buffer ?? secretKey);

export const exportEd25519PublicKey = (publicKey) => bufferToBase64(publicKey.buffer ?? publicKey);

export const importEd25519SecretKey = (base64) => new Uint8Array(base64ToBuffer(base64));

export const importEd25519PublicKey = (base64) => new Uint8Array(base64ToBuffer(base64));

// Canonical JSON: sort object keys alphabetically so key insertion order doesn't affect the signature.
// This ensures sign → RTDB → verify produces consistent results regardless of how the object is transmitted.
const canonicalJson = (obj) => {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return JSON.stringify(obj);
  const sorted = {};
  Object.keys(obj)
    .sort()
    .forEach((k) => {
      sorted[k] = obj[k];
    });
  return JSON.stringify(sorted);
};

export const signWithEd25519 = (payload, secretKey) => {
  const msg = new TextEncoder().encode(canonicalJson(payload));
  const sig = ed25519.sign(msg, secretKey);
  return bufferToBase64(sig.buffer ?? sig);
};

// Sign the raw UTF-8 bytes of a fixed message string (no JSON wrapping) → std-base64 sig.
// Used for the capability revocation message ("kunji-revoke-v1:{jti}"); the RP verifies the
// same bytes against the capability's own key, so no canonical-JSON contract is involved.
export const signMessageEd25519 = (message, secretKey) => {
  const sig = ed25519.sign(new TextEncoder().encode(String(message)), secretKey);
  return bufferToBase64(sig.buffer ?? sig);
};

export const verifyEd25519Signature = (payload, signatureBase64, publicKey) => {
  try {
    const msg = new TextEncoder().encode(canonicalJson(payload));
    const sig = new Uint8Array(base64ToBuffer(signatureBase64));
    return ed25519.verify(sig, msg, publicKey);
  } catch {
    return false;
  }
};
