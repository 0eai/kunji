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

export const deriveKeyArgon2id = async (passkey, saltString) => {
    const salt = new TextEncoder().encode(saltString);
    const hash = await argon2id({
        password: passkey,
        salt: salt,
        iterations: 3,
        memorySize: 65536, // 64 MB
        parallelism: 1,
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
