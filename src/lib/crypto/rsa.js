// lib/crypto/rsa.js — RSA-4096-OAEP key management and encryption

import { bufferToBase64, base64ToBuffer } from './helpers';

// --- Key Management ---

export const generateRSAKeyPair = async () => {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
};

export const exportRSAPublicKey = async (publicKey) => {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    return bufferToBase64(exported);
};

export const exportRSAPrivateKey = async (privateKey) => {
    const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    return bufferToBase64(exported);
};

export const importRSAPublicKey = async (base64) => {
    const buffer = base64ToBuffer(base64);
    return window.crypto.subtle.importKey(
        "spki",
        buffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
};

export const importRSAPrivateKey = async (base64) => {
    const buffer = base64ToBuffer(base64);
    return window.crypto.subtle.importKey(
        "pkcs8",
        buffer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
};

// --- Encryption / Decryption ---

export const encryptRSA = async (dataString, publicKey) => {
    const encoded = new TextEncoder().encode(dataString);
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        encoded
    );
    return bufferToBase64(encrypted);
};

export const decryptRSA = async (base64EncryptedData, privateKey) => {
    try {
        const buffer = base64ToBuffer(base64EncryptedData);

        // Automatically unpack the rsa property if the passed object comes from getMyPrivateKey()
        const validKey = privateKey.rsa ? privateKey.rsa : privateKey;

        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            validKey,
            buffer
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error("RSA Decryption failed", e);
        return null;
    }
};
