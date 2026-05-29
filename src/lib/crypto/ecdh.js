// lib/crypto/ecdh.js — ECDH P-256 key exchange for forward secrecy

import { bufferToBase64, base64ToBuffer } from './helpers';

export const generateECDHKeyPair = async () => {
    return window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
    );
};

export const exportECDHPublicKey = async (publicKey) => {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    return bufferToBase64(exported);
};

export const exportECDHPrivateKey = async (privateKey) => {
    const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    return bufferToBase64(exported);
};

export const importECDHPublicKey = async (base64) => {
    const buffer = base64ToBuffer(base64);
    return window.crypto.subtle.importKey(
        "spki",
        buffer,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    );
};

export const importECDHPrivateKey = async (base64) => {
    const buffer = base64ToBuffer(base64);
    return window.crypto.subtle.importKey(
        "pkcs8",
        buffer,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
    );
};

export const deriveECDHSharedSecret = async (privateKey, publicKey) => {
    return window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
};
