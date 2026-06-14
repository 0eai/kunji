// Signed-write verification — the canonical-JSON + Ed25519 contract shared by the vault-write keypair
// (deriveVaultWriteKeyPair) and the kunji write functions. Pure (no Firebase), so it's unit-testable
// against the client signer (src/lib/crypto/ed25519.js signWithEd25519). The client signs
// canonicalJson(payload) (sorted top-level keys, no whitespace); the function rebuilds the same payload
// (minus signedToken) and verifies the signature against the supplied public key. See functions/index.js.
import { ed25519 } from '@noble/curves/ed25519.js';

// MUST byte-match the client's canonicalJson (src/lib/crypto/ed25519.js) and functions/index.js: sort
// only the TOP-LEVEL keys; nested objects keep their insertion order (JSON round-trips it identically).
export const canonicalJson = (o) =>
  o === null || typeof o !== 'object' || Array.isArray(o)
    ? JSON.stringify(o)
    : JSON.stringify(
        Object.fromEntries(
          Object.keys(o)
            .sort()
            .map((k) => [k, o[k]]),
        ),
      );

const b64 = (s) => Buffer.from(String(s), 'base64');

/** Verify `signedToken` is an Ed25519 signature by `publicKey` over canonicalJson(payload). */
export const verifySignedWrite = (payload, signedToken, publicKey) => {
  try {
    return ed25519.verify(b64(signedToken), new TextEncoder().encode(canonicalJson(payload)), b64(publicKey));
  } catch {
    return false;
  }
};
