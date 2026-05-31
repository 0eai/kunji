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

export const exportEd25519SecretKey = (secretKey) =>
    bufferToBase64(secretKey.buffer ?? secretKey);

export const exportEd25519PublicKey = (publicKey) =>
    bufferToBase64(publicKey.buffer ?? publicKey);

export const importEd25519SecretKey = (base64) =>
    new Uint8Array(base64ToBuffer(base64));

export const importEd25519PublicKey = (base64) =>
    new Uint8Array(base64ToBuffer(base64));

// Canonical JSON: sort object keys alphabetically so key insertion order doesn't affect the signature.
// This ensures sign → RTDB → verify produces consistent results regardless of how the object is transmitted.
const canonicalJson = (obj) => {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return JSON.stringify(obj);
    const sorted = {};
    Object.keys(obj).sort().forEach(k => { sorted[k] = obj[k]; });
    return JSON.stringify(sorted);
};

export const signWithEd25519 = (payload, secretKey) => {
    const msg = new TextEncoder().encode(canonicalJson(payload));
    const sig = ed25519.sign(msg, secretKey);
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
