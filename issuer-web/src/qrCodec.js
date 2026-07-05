/**
 * Compact login-QR encoding ("K1") — the single source of truth for both sides.
 *
 * The login QR historically carried mixed-case JSON, which forces the QR encoder into BYTE mode
 * (8 bits/char) → a dense code. `K1` packs the same request into a tiny binary struct and base32-encodes
 * it, so the whole string is `[0-9A-Z:]` — inside the QR ALPHANUMERIC charset
 * (`/^[0-9A-Z $%*+\-./:]*$/`) — and qr-code-styling / qrcode auto-select alphanumeric mode (5.5 bits/char).
 *
 *     K1:<base32-nopad( struct )>
 *
 * The struct stores `sessionId`/`challenge` as RAW BYTES when they're base64url (the common case — the
 * demo mints base64url), which avoids re-encoding already-encoded entropy; anything else (hex, opaque)
 * is stored as UTF-8 (a per-field flag records which, guarded by a base64url round-trip check, so it is
 * always lossless and never assumes a format it can't reproduce). All other field CONTENT (lowercase app
 * names, `vc:age_over_18` scopes, custom callbacks) is safe because it lives inside the base32 blob.
 *
 * The wallet's `parseQRPayload` accepts BOTH this and the legacy JSON payload (dispatch by the `K1:`
 * prefix). The same-device `?approve=` deep link stays JSON (length is free there).
 *
 * Pure + dependency-free (TextEncoder/TextDecoder + atob/btoa — browser + Node). Keep it that way: it is
 * bundled into rp.js (widget), imported by the wallet + the demo, and copied byte-for-byte into issuer-web
 * (parity-guarded by tests/qrCodec.parity.test.js).
 */

const PREFIX = 'K1:';
const VERSION = 1;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // RFC 4648, no padding
// flags byte
const F_S_RAW = 1; // sessionId stored as raw (base64url-decoded) bytes, else UTF-8
const F_C_RAW = 2; // challenge  stored as raw bytes, else UTF-8
const F_HAS_N = 4; // appName present
const F_HAS_K = 8; // callbackUrl present
const F_HAS_P = 16; // scope present

// ── base32 (RFC 4648, no padding) over raw bytes ────────────────────────────
const base32Encode = (bytes) => {
  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
};
const base32Decode = (str) => {
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (let i = 0; i < str.length; i++) {
    const idx = B32.indexOf(str[i]);
    if (idx === -1) throw new Error('bad_base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
};

// ── base64url ↔ bytes (for the session/challenge single-encode optimization) ─
const b64urlToBytes = (str) => {
  if (!/^[A-Za-z0-9_-]+$/.test(str)) return null;
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};
const bytesToB64url = (bytes) => {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/** Is `str` a compact K1 QR string? */
export const isCompactQr = (str) => typeof str === 'string' && str.startsWith(PREFIX);

/**
 * Encode a login request into a compact `K1:` string. `payload` is the normalized request
 * ({ sessionId, challenge, audience, expiresAt, appName?, callbackUrl?, scope? }); only defined optional
 * fields are emitted. Pure serializer — the caller decides what to include (e.g. omit callbackUrl when
 * it's the same-site default).
 */
export const encodeCompactQr = (payload) => {
  const enc = new TextEncoder();
  let flags = 0;

  // sessionId/challenge: store raw bytes when base64url round-trips exactly (lossless), else UTF-8.
  const packToken = (str, rawBit) => {
    const bytes = b64urlToBytes(str);
    if (bytes && bytesToB64url(bytes) === str) {
      flags |= rawBit;
      return bytes;
    }
    return enc.encode(str);
  };
  const fields = [
    packToken(String(payload.sessionId), F_S_RAW),
    packToken(String(payload.challenge), F_C_RAW),
    enc.encode(String(payload.audience)),
    enc.encode(String(payload.expiresAt)), // decimal string — universal for any numeric expiry
  ];
  if (payload.appName) {
    flags |= F_HAS_N;
    fields.push(enc.encode(String(payload.appName)));
  }
  if (payload.callbackUrl) {
    flags |= F_HAS_K;
    fields.push(enc.encode(String(payload.callbackUrl)));
  }
  if (Array.isArray(payload.scope) && payload.scope.length) {
    flags |= F_HAS_P;
    fields.push(enc.encode(JSON.stringify(payload.scope)));
  }

  const total = 2 + fields.reduce((n, f) => n + 2 + f.length, 0); // version + flags + (u16 len + bytes)*
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  let o = 0;
  buf[o++] = VERSION;
  buf[o++] = flags;
  for (const f of fields) {
    if (f.length > 0xffff) throw new Error('field_too_long');
    dv.setUint16(o, f.length);
    o += 2;
    buf.set(f, o);
    o += f.length;
  }
  return PREFIX + base32Encode(buf);
};

/**
 * Decode a compact `K1:` string back to the normalized login payload shape that `parseQRPayload` then
 * validates. Throws on any malformed input (the caller maps that to `invalid_qr`). Sets `kunjiAuth:'v2'`
 * so the shared validation gate treats it identically to a JSON payload.
 */
export const decodeCompactQr = (str) => {
  if (!isCompactQr(str)) throw new Error('not_compact_qr');
  const buf = base32Decode(str.slice(PREFIX.length));
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const dec = new TextDecoder();
  let o = 0;
  if (buf[o++] !== VERSION) throw new Error('bad_version');
  const flags = buf[o++];
  const readField = () => {
    const len = dv.getUint16(o); // throws RangeError past end → caught upstream as invalid_qr
    o += 2;
    if (o + len > buf.length) throw new Error('truncated');
    const bytes = buf.subarray(o, o + len);
    o += len;
    return bytes;
  };
  const sB = readField();
  const cB = readField();
  const aB = readField();
  const eB = readField();
  const out = {
    kunjiAuth: 'v2',
    sessionId: flags & F_S_RAW ? bytesToB64url(sB) : dec.decode(sB),
    challenge: flags & F_C_RAW ? bytesToB64url(cB) : dec.decode(cB),
    audience: dec.decode(aB),
    expiresAt: Number(dec.decode(eB)),
  };
  if (flags & F_HAS_N) out.appName = dec.decode(readField());
  if (flags & F_HAS_K) out.callbackUrl = dec.decode(readField());
  if (flags & F_HAS_P) out.scope = JSON.parse(dec.decode(readField()));
  return out;
};
