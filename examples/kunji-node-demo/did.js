/**
 * Minimal DID resolution for the OpenID4VP `did` client_id scheme (docs/oid4vc.md §5).
 *
 * Two methods, both yielding the verifier's Ed25519 (OKP) signing key so the existing EdDSA JWS path
 * verifies the request:
 *   - `did:jwk:<base64url(JSON jwk)>` — the key IS the identifier; no fetch, no network trust. It
 *     authenticates the request but provides NO origin binding (the caller must bind the response some
 *     other way — kunji requires an encrypted response for did:jwk; see oid4vc.js).
 *   - `did:web:<host>[:path…]` — resolves to `https://<host>/[path/]did.json` (HTTPS-only by construction),
 *     equivalent assurance to kunji's `.well-known` HTTPS-anchored scheme.
 *
 * Pure + isomorphic (only `atob` + `fetch`), so the demo Node port is byte-identical. No new dependency.
 */

// base64url → UTF-8 string (atob is a standard global in browsers and Node ≥16).
const b64uToString = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
  const bin = atob(t + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
};

/** `did:jwk:<base64url(JSON jwk)>` → the embedded JWK. Throws on a malformed DID. */
export const parseDidJwk = (did) => {
  const m = /^did:jwk:([A-Za-z0-9_-]+)$/.exec(String(did || ''));
  if (!m) throw new Error('bad_did');
  let jwk;
  try {
    jwk = JSON.parse(b64uToString(m[1]));
  } catch {
    throw new Error('bad_did');
  }
  return jwk;
};

/** `did:web:host[:path:segs]` → `https://host/[path/segs/]did.json` (RFC: percent-decoded, `:`→`/`). */
export const didWebToUrl = (did) => {
  const m = /^did:web:(.+)$/.exec(String(did || ''));
  if (!m) throw new Error('bad_did');
  const parts = m[1].split(':').map(decodeURIComponent);
  const host = parts.shift();
  if (!host) throw new Error('bad_did');
  return parts.length ? `https://${host}/${parts.join('/')}/did.json` : `https://${host}/.well-known/did.json`;
};

/**
 * Resolve a DID to its OKP verification-method JWK. `did:jwk` returns the embedded key (no fetch);
 * `did:web` fetches the DID document (HTTPS-only by construction) and selects the verification method by
 * `kid` (matched against the method `id`, exact or `#fragment`), else the first OKP method. `fetchImpl`
 * is injectable for tests.
 * @returns {Promise<object>} an OKP JWK (the caller verifies the EdDSA JWS against it)
 */
export const resolveDidKey = async (did, { kid, fetchImpl = fetch } = {}) => {
  if (String(did || '').startsWith('did:jwk:')) return parseDidJwk(did);
  if (String(did || '').startsWith('did:web:')) {
    let resp;
    try {
      resp = await fetchImpl(didWebToUrl(did));
    } catch {
      throw new Error('did_unresolved');
    }
    if (!resp.ok) throw new Error('did_unresolved');
    let doc;
    try {
      doc = await resp.json();
    } catch {
      throw new Error('did_unresolved');
    }
    const methods = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
    const okp = methods.filter((m) => m.publicKeyJwk && m.publicKeyJwk.kty === 'OKP');
    const pick = kid
      ? okp.find((m) => m.id === kid || String(m.id || '').endsWith(`#${kid}`))
      : okp[0];
    if (!pick) throw new Error('did_key_not_found');
    return pick.publicKeyJwk;
  }
  throw new Error('bad_did');
};
