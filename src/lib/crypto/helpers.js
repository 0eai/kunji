// lib/crypto/helpers.js — Shared buffer ↔ base64 helpers (internal)

export const bufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const len = bytes.byteLength;
    const chunkSize = 32768;
    for (let i = 0; i < len; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return window.btoa(binary);
};

export const base64ToBuffer = (base64) => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

// Canonicalize a domain/audience so per-app identity derivation is stable: lowercase,
// trim, drop a trailing dot and a default :80/:443 port. Applied at the derivation
// boundary so "Example.com", "example.com." and "example.com:443" map to one identity.
export const normalizeDomain = (domain) =>
    String(domain || '').trim().toLowerCase().replace(/\.$/, '').replace(/:(80|443)$/, '');
