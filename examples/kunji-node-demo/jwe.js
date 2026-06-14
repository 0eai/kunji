/**
 * Minimal JWE for OpenID4VP encrypted responses (`response_mode: direct_post.jwt`) — docs/oid4vc.md §5.
 *
 * One pinned algorithm: **`alg: ECDH-ES`** (direct key agreement, no key wrapping) + **`enc: A256GCM`**,
 * JWE compact serialization. The wallet encrypts its `vp_token` response to the verifier's published P-256
 * encryption key so an on-path observer / the direct_post transport can't read the credential
 * presentation. Pure + isomorphic — only `globalThis.crypto.subtle` (ECDH deriveBits, AES-GCM, SHA-256) —
 * so the demo Node port is byte-identical. No credential-core dependency; this only wraps the response.
 *
 * Compact: BASE64URL(protected) . (empty — ECDH-ES gives the CEK directly) . iv . ciphertext . tag.
 * CEK = Concat-KDF(Z) where Z = ECDH(ephemeral, recipient). See RFC 7518 §4.6 (ECDH-ES) + NIST SP 800-56A.
 */
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();
const ENC = 'A256GCM';

// Portable base64url (no Buffer/btoa) so wallet + Node port are byte-identical.
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const toB64u = (bytes) => {
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
const fromB64u = (str) => {
  const L = {};
  for (let i = 0; i < B64.length; i++) L[B64[i]] = i;
  const s = String(str);
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const a = L[s[i]];
    const b = L[s[i + 1]];
    const c = L[s[i + 2]];
    const d = L[s[i + 3]];
    out.push((a << 2) | (b >> 4));
    if (c !== undefined) out.push(((b & 15) << 4) | (c >> 2));
    if (d !== undefined) out.push(((c & 3) << 6) | d);
  }
  return new Uint8Array(out);
};
const u32be = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};

const importEcdh = (jwk, usages) =>
  subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', ...jwk }, { name: 'ECDH', namedCurve: 'P-256' }, false, usages);

// ECDH-ES Concat-KDF (NIST SP 800-56A single-step, SHA-256) → the 256-bit A256GCM content key. For
// alg=ECDH-ES (Direct), AlgorithmID is the `enc` value. apu/apv omitted (empty). keydatalen=256 → one
// SHA-256 block, so K = SHA-256( counter(1) || Z || OtherInfo ).
const deriveCek = async (zBits) => {
  const algId = te.encode(ENC);
  const otherInfo = concat(u32be(algId.length), algId, u32be(0), u32be(0), u32be(256)); // AlgID | apu | apv | keydatalen
  const input = concat(u32be(1), new Uint8Array(zBits), otherInfo);
  const digest = await subtle.digest('SHA-256', input);
  return subtle.importKey('raw', digest, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
};

const ecdhZ = (privateKey, publicKey) =>
  subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256); // 256-bit P-256 shared X

/**
 * Encrypt `payloadObj` (JSON) to the recipient's P-256 ECDH public JWK. Returns a JWE compact string.
 * Generates a fresh ephemeral keypair per call (the `epk` in the protected header).
 */
export const encryptJwe = async (payloadObj, recipientPublicJwk) => {
  const recipient = await importEcdh(recipientPublicJwk, []);
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const epk = await subtle.exportKey('jwk', eph.publicKey);
  const protectedHeader = { alg: 'ECDH-ES', enc: ENC, epk: { kty: 'EC', crv: 'P-256', x: epk.x, y: epk.y } };
  const protectedB64 = toB64u(te.encode(JSON.stringify(protectedHeader)));
  const cek = await deriveCek(await ecdhZ(eph.privateKey, recipient));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: te.encode(protectedB64), tagLength: 128 },
      cek,
      te.encode(JSON.stringify(payloadObj)),
    ),
  );
  // WebCrypto appends the 16-byte tag to the ciphertext; JWE keeps them separate.
  const tag = ct.slice(ct.length - 16);
  const ciphertext = ct.slice(0, ct.length - 16);
  return `${protectedB64}..${toB64u(iv)}.${toB64u(ciphertext)}.${toB64u(tag)}`; // empty encrypted_key (ECDH-ES direct)
};

/**
 * Decrypt a JWE compact string with the recipient's P-256 ECDH private JWK → the JSON payload object.
 * Throws on any malformation, wrong key, or tag mismatch.
 */
export const decryptJwe = async (compact, recipientPrivateJwk) => {
  const parts = String(compact).split('.');
  if (parts.length !== 5) throw new Error('malformed_jwe');
  const [protectedB64, , ivB64, ctB64, tagB64] = parts;
  const header = JSON.parse(td.decode(fromB64u(protectedB64)));
  if (header.alg !== 'ECDH-ES' || header.enc !== ENC || !header.epk) throw new Error('unsupported_jwe');
  const priv = await importEcdh(recipientPrivateJwk, ['deriveBits']);
  const eph = await importEcdh(header.epk, []);
  const cek = await deriveCek(await ecdhZ(priv, eph));
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64u(ivB64), additionalData: te.encode(protectedB64), tagLength: 128 },
    cek,
    concat(fromB64u(ctB64), fromB64u(tagB64)), // WebCrypto wants ciphertext||tag
  );
  return JSON.parse(td.decode(new Uint8Array(pt)));
};

/** Generate a P-256 ECDH keypair for a verifier's encryption key → { publicJwk, privateJwk }. */
export const generateJweKeyPair = async () => {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicJwk = await subtle.exportKey('jwk', kp.publicKey);
  const privateJwk = await subtle.exportKey('jwk', kp.privateKey);
  return {
    publicJwk: { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y, use: 'enc', alg: 'ECDH-ES' },
    privateJwk,
  };
};
