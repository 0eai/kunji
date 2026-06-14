/**
 * BBS primitive wrapper — verified-credentials.md §7 tier v3 (unlinkable selective disclosure).
 *
 * A thin, dependency-pinned layer over @digitalbazaar/bbs-signatures (pure JS over @noble/curves —
 * the SAME curve lib kunji already uses; runs in browser + Node, no WASM). It pins ONE ciphersuite
 * (BLS12-381-SHA-256) and adds a portable base64url + message encoder so the credential layer
 * (`vcBbs.js`) and the demo Node ports can stay byte-identical across environments.
 *
 * BBS lets an issuer sign a VECTOR of messages with one short signature; the holder then derives a
 * fresh, RANDOMIZED zero-knowledge proof that reveals only a chosen subset and binds to a presentation
 * header (aud+nonce). Two proofs from the same signature are unlinkable — the v3 property. This module
 * is pure crypto plumbing; the credential format lives in `vcBbs.js`. See docs/verified-credentials.md.
 */
import {
  CIPHERSUITES,
  generateKeyPair,
  secretKeyToPublicKey,
  sign,
  verifySignature,
  deriveProof,
  verifyProof,
} from '@digitalbazaar/bbs-signatures';

// One pinned ciphersuite for the whole protocol (issuer ↔ wallet ↔ verifier must agree).
export const BBS_CIPHERSUITE = CIPHERSUITES.BLS12381_SHA256;

const enc = new TextEncoder();

// Portable base64url (no Buffer/btoa) so this module is byte-identical in the browser wallet and the
// plain-Node demo ports. Operates on/produces Uint8Array.
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export const bytesToB64u = (bytes) => {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    out += B64[a >> 2] + B64[((a & 3) << 4) | ((b ?? 0) >> 4)];
    if (b !== undefined) out += B64[((b & 15) << 2) | ((c ?? 0) >> 6)];
    if (c !== undefined) out += B64[c & 63];
  }
  return out;
};
export const b64uToBytes = (str) => {
  const L = {};
  for (let i = 0; i < B64.length; i++) L[B64[i]] = i;
  const s = String(str);
  const bytes = [];
  for (let i = 0; i < s.length; i += 4) {
    const a = L[s[i]];
    const b = L[s[i + 1]];
    const c = L[s[i + 2]];
    const d = L[s[i + 3]];
    bytes.push((a << 2) | (b >> 4));
    if (c !== undefined) bytes.push(((b & 15) << 4) | (c >> 2));
    if (d !== undefined) bytes.push(((c & 3) << 6) | d);
  }
  return new Uint8Array(bytes);
};

/** UTF-8 bytes of a string (BBS messages/headers are byte strings). */
export const bbsBytes = (str) => enc.encode(String(str));

/** A fresh BBS keypair ({ secretKey:32B, publicKey:96B } Uint8Arrays). */
export const bbsKeyGen = async () => generateKeyPair({ ciphersuite: BBS_CIPHERSUITE });

/** Derive the BBS public key from a secret key. */
export const bbsPublicFromSecret = async (secretKey) =>
  secretKeyToPublicKey({ secretKey, ciphersuite: BBS_CIPHERSUITE });

/** Issuer: sign a vector of byte messages under a (revealed) header. */
export const bbsSign = async ({ secretKey, publicKey, header, messages }) =>
  sign({ secretKey, publicKey, header, messages, ciphersuite: BBS_CIPHERSUITE });

/** Verify an issuer signature over the full message vector (issuer-side / tests). */
export const bbsVerify = async ({ publicKey, signature, header, messages }) =>
  verifySignature({ publicKey, signature, header, messages, ciphersuite: BBS_CIPHERSUITE });

/**
 * Holder: derive a randomized ZK proof revealing only `disclosedMessageIndexes`, bound to
 * `presentationHeader` (aud+nonce). Each call produces a fresh, unlinkable proof.
 */
export const bbsDeriveProof = async ({ publicKey, signature, header, messages, presentationHeader, disclosedMessageIndexes }) =>
  deriveProof({
    publicKey,
    signature,
    header,
    messages,
    presentationHeader,
    disclosedMessageIndexes,
    ciphersuite: BBS_CIPHERSUITE,
  });

/**
 * Verifier: check a proof against the issuer's public key + the disclosed messages at their indexes
 * and the presentation header. The disclosed message bytes are cryptographically bound to their
 * indexes, so a holder can neither alter a value nor relabel an index.
 */
export const bbsVerifyProof = async ({ publicKey, proof, header, presentationHeader, disclosedMessages, disclosedMessageIndexes }) =>
  verifyProof({
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedMessageIndexes,
    ciphersuite: BBS_CIPHERSUITE,
  });
