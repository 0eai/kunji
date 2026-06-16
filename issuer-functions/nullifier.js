// Issuer-side uniqueness nullifier (roadmap 2.2). Turns a credential type's normalized ID pre-image
// (credentials.js `nullifierFrom`) into a per-issuer, one-way digest used to record "this real ID has
// been issued personhood" — WITHOUT storing the raw ID. Properties that matter:
//
//   • Secret-keyed: the issuer-only `secret` (KUNJI_NULLIFIER_KEY) is the scrypt salt/pepper. Without it,
//     the digest cannot be computed at all — so even a Firestore/backup leak of the nullifier table is not
//     a membership oracle on its own.
//   • Memory-hard (scrypt, N=2^15 ≈ 32 MB/guess): if the secret ALSO leaks, this blunts MASS enumeration of
//     a country's (low-entropy) ID-number space — turning "enumerate everyone" into "test a few known
//     suspects". (It can't defeat a targeted guess of a known ID — nothing keyed can.)
//   • Deterministic: same pre-image + same secret → same nullifier, so re-verification of the same ID is
//     idempotent (one human, not a second identity). Runs once per operator APPROVAL (human-rate), so the
//     ~tens-of-ms cost is irrelevant.
//
// The result is NEVER placed in the credential, the claims, or the ledger — only in the deny-all
// `issuerNullifiers` collection. Built on Node's `crypto.scryptSync` (no new dependency, no WASM).
import { scryptSync } from 'node:crypto';

// scrypt cost: N=32768, r=8, p=1 → ~32 MB working set per evaluation (maxmem bumped to allow it).
const PARAMS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export const nullifierDigest = (preimage, secret) => {
  if (!preimage || !secret) throw new Error('nullifier_inputs');
  // secret acts as the salt/pepper — deterministic per (preimage, secret); base64url is Firestore-doc-id safe.
  return scryptSync(String(preimage), String(secret), 32, PARAMS).toString('base64url');
};
