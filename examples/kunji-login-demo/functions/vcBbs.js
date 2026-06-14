/**
 * Verified credentials — BBS format (holder + verifier). The unlinkable tier (v3).
 *
 * A trusted ISSUER BBS-signs a credential: an always-revealed `header` ({iss, vct, exp}) plus a VECTOR
 * of claim messages (one per claim, `name=value`). The holder presents by deriving a fresh, RANDOMIZED
 * zero-knowledge `proof` that reveals only the chosen claims and binds to the verifier's (aud, nonce)
 * via a presentation header. Two presentations of the SAME credential share NO correlation handle — no
 * signature, no holder key — so they're unlinkable even to colluding verifiers, from ONE credential
 * (v2 needed N one-time copies for this). The RP verifies LOCALLY against the issuer's BBS key (from its
 * `.well-known`), no kunji backend in the path.
 *
 * Parallel to `vc.js` (SD-JWT) — kunji holds both formats; this module never touches the SD-JWT core.
 * Pure + isomorphic (over `bbs.js`), so the demo Node ports are byte-identical. Replay protection comes
 * from the presentation header; holder binding (non-transferability) is a deferred next slice — until
 * then a BBS credential blob is transferable. See docs/verified-credentials.md §7.
 */
import { bbsBytes, bytesToB64u, b64uToBytes, bbsKeyGen, bbsPublicFromSecret, bbsSign, bbsDeriveProof, bbsVerifyProof } from './bbs.js';

export { bbsKeyGen, bbsPublicFromSecret };

const DAY = 86400;

// Canonical JSON (sorted keys) so the issuer's signed bytes and the verifier's reconstructed bytes match.
const canon = (obj) => {
  const sorted = {};
  for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
  return JSON.stringify(sorted);
};

// One BBS message per claim, encoding BOTH name and value — so a holder can neither alter a disclosed
// value nor relabel an index (the message bytes are bound to their index by the proof).
const claimMessage = (name, value) => bbsBytes(`${name}=${JSON.stringify(value)}`);

// A BBS presentation travels on the wire as a TAGGED STRING (not a nested object): the login assertion
// is signed over canonical JSON that sorts only top-level keys, and the SD-JWT vp_token/vc_presentations
// are already strings — so a tagged string keeps every wire string-typed and lets verifiers dispatch by
// the `bbs~` prefix without disturbing signing/canonicalization. See docs/oid4vc.md.
const BBS_PRESENTATION_TAG = 'bbs~';
export const isBbsPresentation = (s) => typeof s === 'string' && s.startsWith(BBS_PRESENTATION_TAG);
export const encodeBbsPresentation = (presentation) =>
  BBS_PRESENTATION_TAG + bytesToB64u(bbsBytes(JSON.stringify(presentation)));
export const decodeBbsPresentation = (s) => {
  if (!isBbsPresentation(s)) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64uToBytes(s.slice(BBS_PRESENTATION_TAG.length))));
  } catch {
    return null;
  }
};

/**
 * Issuer: mint a BBS credential bound to `claims`. The header ({iss, vct, exp}) is always revealed at
 * presentation, so `exp` is coarsened to the UTC-day boundary (a large anonymity set — it must not be a
 * per-credential handle; the v2 §7/S23 lesson). Claim names are sorted to a stable signed order so the
 * holder's disclose-by-name maps to the right message indexes. Returns a serializable credential blob.
 */
export const mintBbsCredential = async (issuerSecretKey, issuerPublicKey, { iss, vct, claims, ttlSeconds, now = Date.now() }) => {
  const iat = Math.floor(now / 1000 / DAY) * DAY;
  const exp = iat + Math.max(DAY, Math.floor((ttlSeconds || 0) / DAY) * DAY);
  const names = Object.keys(claims || {}).sort();
  const values = names.map((n) => claims[n]);
  const header = bbsBytes(canon({ iss, vct, exp }));
  const messages = names.map((n) => claimMessage(n, claims[n]));
  const signature = await bbsSign({ secretKey: issuerSecretKey, publicKey: issuerPublicKey, header, messages });
  return {
    format: 'bbs',
    iss,
    vct,
    exp,
    names, // claim names in signed order
    values, // claim values the holder holds (selectively disclosed at presentation)
    header: bytesToB64u(header),
    signature: bytesToB64u(signature),
  };
};

/** Claim names a BBS credential can disclose (for the wallet list UI). */
export const bbsClaimNames = (credential) => (credential?.names || []).slice();

/**
 * Holder: derive a presentation revealing only `disclose` (claim names), bound to (audience, nonce).
 * `issuerPublicKey` is the issuer's BBS public key (resolved from its `.well-known`). The returned proof
 * is fresh + randomized — unlinkable across presentations. Returns a serializable presentation blob.
 */
export const buildBbsPresentation = async ({ credential, disclose, audience, nonce, issuerPublicKey }) => {
  const header = b64uToBytes(credential.header);
  const messages = credential.names.map((n, i) => claimMessage(n, credential.values[i]));
  const want = new Set(disclose || []);
  const disclosedMessageIndexes = credential.names.map((n, i) => (want.has(n) ? i : -1)).filter((i) => i >= 0);
  const presentationHeader = bbsBytes(canon({ aud: audience, nonce }));
  const proof = await bbsDeriveProof({
    publicKey: issuerPublicKey,
    signature: b64uToBytes(credential.signature),
    header,
    messages,
    presentationHeader,
    disclosedMessageIndexes,
  });
  return {
    format: 'bbs',
    iss: credential.iss,
    vct: credential.vct,
    header: credential.header, // revealed; the verifier re-reads iss/vct/exp from it
    proof: bytesToB64u(proof),
    disclosed: disclosedMessageIndexes.map((i) => ({ name: credential.names[i], value: credential.values[i] })),
    disclosedIndexes: disclosedMessageIndexes,
    audience,
    nonce,
  };
};

/**
 * Verifier (RP-side; also the reference the demo's Node port mirrors). `getIssuerBbsKey(iss)` resolves
 * the issuer's BBS public key bytes (from its `.well-known` — injectable, so tests run offline). Checks
 * the header (iss/vct/exp + freshness), then the BBS proof over the disclosed messages + the rebuilt
 * presentation header (aud, nonce). The disclosed values are cryptographically bound to their indexes.
 * @returns {Promise<{ ok:true, iss, vct, claims } | { ok:false, error }>}
 */
export const verifyBbsPresentation = async ({ presentation, getIssuerBbsKey, audience, nonce, now = Date.now() }) => {
  let header;
  let hdr;
  try {
    header = b64uToBytes(presentation.header);
    hdr = JSON.parse(new TextDecoder().decode(header));
  } catch {
    return { ok: false, error: 'bad_header' };
  }
  if (!hdr?.iss) return { ok: false, error: 'no_issuer' };
  if (presentation.iss && presentation.iss !== hdr.iss) return { ok: false, error: 'iss_mismatch' };
  if (typeof hdr.exp !== 'number' || now > hdr.exp * 1000) return { ok: false, error: 'credential_expired' };

  let issuerPublicKey;
  try {
    issuerPublicKey = await getIssuerBbsKey(hdr.iss);
  } catch {
    return { ok: false, error: 'issuer_unresolved' };
  }
  if (!(issuerPublicKey instanceof Uint8Array)) return { ok: false, error: 'bad_issuer_key' };

  const presentationHeader = bbsBytes(canon({ aud: audience, nonce }));
  const disclosed = presentation.disclosed || [];
  const disclosedMessages = disclosed.map((d) => claimMessage(d.name, d.value));
  const disclosedMessageIndexes = presentation.disclosedIndexes || [];
  if (disclosedMessages.length !== disclosedMessageIndexes.length) return { ok: false, error: 'disclosure_mismatch' };

  let ok;
  try {
    ok = await bbsVerifyProof({
      publicKey: issuerPublicKey,
      proof: b64uToBytes(presentation.proof),
      header,
      presentationHeader,
      disclosedMessages,
      disclosedMessageIndexes,
    });
  } catch {
    return { ok: false, error: 'bad_proof' };
  }
  if (!ok) return { ok: false, error: 'bad_proof' };

  const claims = {};
  for (const d of disclosed) claims[d.name] = d.value;
  return { ok: true, iss: hdr.iss, vct: hdr.vct, claims };
};
