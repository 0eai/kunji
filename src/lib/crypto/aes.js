// lib/crypto/aes.js — AES-256-GCM encryption/decryption + key management

import { bufferToBase64, base64ToBuffer } from './helpers';
import { argon2id } from 'hash-wasm';

// Configuration
const DEFAULT_ITERATIONS = 600000; // OWASP 2024 recommendation for SHA-256
const ALGO_NAME = "AES-GCM";
const HASH_NAME = "SHA-256";

// --- Key Management ---

export const generateSalt = () => {
    const randomValues = new Uint8Array(16);
    window.crypto.getRandomValues(randomValues);
    return Array.from(randomValues).map(b => b.toString(16).padStart(2, '0')).join('');
};

export const getDefaultIterations = () => DEFAULT_ITERATIONS;

export const generateMasterKey = async () => {
    return window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
};

export const exportKey = async (key) => {
    return window.crypto.subtle.exportKey("jwk", key);
};

export const importMasterKey = async (jwkData) => {
    return window.crypto.subtle.importKey(
        "jwk",
        jwkData,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
    );
};

// --- Key Derivation ---

export const deriveKeyFromPasskey = async (passkey, saltString, iterations = DEFAULT_ITERATIONS) => {
    const textEncoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        textEncoder.encode(passkey),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: textEncoder.encode(saltString),
            iterations: iterations,
            hash: HASH_NAME
        },
        keyMaterial,
        { name: ALGO_NAME, length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

// Derive a stable, high-entropy vault id from the master key. Every device that
// holds the same master key computes the same id, so shared data (the apps list)
// can live under vaults/{vaultId} and sync across linked devices automatically.
export const deriveVaultId = async (masterKey) => {
    const raw = await window.crypto.subtle.exportKey('raw', masterKey);
    const ikm = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
    const bits = await window.crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('kunji-vault-id-v1'),
            info: new TextEncoder().encode('kunji-vault-id'),
        },
        ikm,
        256,
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
};

// Argon2id work factor. V2 is the current target; LEGACY is the original hardcoded
// config used by vaults wrapped before per-user params were stored. Params are
// persisted per-user (the `argon2` field), so each vault carries the params needed
// to unlock it — strength can be raised later without locking out existing vaults.
export const ARGON2_DEFAULTS = { memorySize: 262144, iterations: 4, parallelism: 1 }; // 256 MB
export const ARGON2_LEGACY  = { memorySize: 65536,  iterations: 3, parallelism: 1 }; // 64 MB

// Map a stored user doc → Argon2id params (legacy if the doc predates the `argon2` field).
export const argon2ParamsFromDoc = (data) => {
    const a = data?.argon2;
    if (!a) return ARGON2_LEGACY;
    return { memorySize: a.m, iterations: a.t, parallelism: a.p };
};

// Map params → the compact `argon2` doc field shape.
export const argon2DocFields = (params) => ({ m: params.memorySize, t: params.iterations, p: params.parallelism });

export const deriveKeyArgon2id = async (passkey, saltString, params = ARGON2_DEFAULTS) => {
    const salt = new TextEncoder().encode(saltString);
    const hash = await argon2id({
        password: passkey,
        salt: salt,
        iterations: params.iterations,
        memorySize: params.memorySize,
        parallelism: params.parallelism,
        hashLength: 32,    // 256-bit key
        outputType: 'binary',
    });

    return window.crypto.subtle.importKey(
        "raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
};

// --- Encryption / Decryption ---

export const encryptData = async (data, key) => {
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: ALGO_NAME, iv: iv },
        key,
        encoded
    );

    return {
        iv: bufferToBase64(iv),
        data: bufferToBase64(encrypted)
    };
};

export const decryptData = async (encryptedObj, key) => {
    try {
        if (!encryptedObj || !encryptedObj.iv || !encryptedObj.data) return null;

        const iv = base64ToBuffer(encryptedObj.iv);
        const data = base64ToBuffer(encryptedObj.data);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: ALGO_NAME, iv: iv },
            key,
            data
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
    } catch (e) {
        console.error("Decryption failed", e);
        return null;
    }
};

export const keyToUrlString = async (key) => {
    const exported = await window.crypto.subtle.exportKey("raw", key);
    const bytes = new Uint8Array(exported);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // URL-safe Base64
};

export const keyFromUrlString = async (base64) => {
    // Add padding back if needed
    let str = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';

    const binary_string = window.atob(str);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }

    return window.crypto.subtle.importKey(
        "raw",
        bytes.buffer,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
};
