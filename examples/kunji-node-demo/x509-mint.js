// Demo/test-only DER X.509 ENCODER + ES256 JWS signer for the `x509_san_dns` client_id scheme.
// The wallet never mints certs, so this lives OUTSIDE the byte-identical x509.js (parser/verifier). It
// builds a minimal P-256 / ECDSA-with-SHA256 self-signed (or CA→leaf) cert carrying a SAN dNSName, so the
// verifier demo + tests can exercise x509.js. Not a general X.509 library.
import { p256 } from '@noble/curves/nist.js';

const der = (tag, content) => {
  const len = content.length;
  let lenBytes;
  if (len < 0x80) lenBytes = [len];
  else {
    const b = [];
    let n = len;
    while (n > 0) {
      b.unshift(n & 0xff);
      n >>= 8;
    }
    lenBytes = [0x80 | b.length, ...b];
  }
  return new Uint8Array([tag, ...lenBytes, ...content]);
};
const cat = (...arrs) => {
  const out = [];
  for (const a of arrs) out.push(...a);
  return new Uint8Array(out);
};
const oid = (bytes) => der(0x06, bytes);
const intDer = (bytes) => {
  let v = Array.from(bytes);
  while (v.length > 1 && v[0] === 0) v.shift();
  if (v[0] & 0x80) v.unshift(0x00); // keep positive
  return der(0x02, v);
};
const seq = (...items) => der(0x30, cat(...items));
const set = (...items) => der(0x31, cat(...items));
const bitString = (bytes) => der(0x03, cat([0x00], bytes)); // 0 unused bits
const utcTime = (ms) => {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return der(0x17, new TextEncoder().encode(s));
};
const ctx = (n, content, constructed = true) => der(0xa0 | n | (constructed ? 0x20 : 0), content);

const OID = {
  ecdsaSha256: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
  ecPublicKey: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
  prime256v1: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  cn: [0x55, 0x04, 0x03],
  san: [0x55, 0x1d, 0x11],
};
const name = (cn) => seq(set(seq(oid(OID.cn), der(0x13, new TextEncoder().encode(cn)))));
const spkiOf = (pubPoint) => seq(seq(oid(OID.ecPublicKey), oid(OID.prime256v1)), bitString(pubPoint));
const sanExt = (dns) => {
  const generalNames = seq(der(0x82, new TextEncoder().encode(dns))); // [2] IA5String dNSName
  return seq(oid(OID.san), der(0x04, generalNames)); // extnValue OCTET STRING wraps GeneralNames
};
const compactToDerSig = (compact) => seq(intDer(compact.subarray(0, 32)), intDer(compact.subarray(32, 64)));

/**
 * Mint a DER X.509 certificate (ECDSA-P256-SHA256) with a SAN dNSName. Self-signed when issuerKey is
 * omitted. Returns { der: Uint8Array, key } where key = { secretKey, publicKey(uncompressed point) }.
 */
export const mintCert = ({ dnsName, subjectKey, issuerKey, issuerDns, notBeforeMs = Date.now() - 3600_000, notAfterMs = Date.now() + 3600_000, serial = 1 }) => {
  const sk = subjectKey?.secretKey || p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(sk, false); // uncompressed 0x04||X||Y
  const issuerSk = issuerKey?.secretKey || sk; // self-signed if no issuer
  const tbs = seq(
    ctx(0, intDer([0x02])), // version v3
    intDer([serial & 0xff]),
    seq(oid(OID.ecdsaSha256)),
    name(issuerDns || dnsName),
    seq(utcTime(notBeforeMs), utcTime(notAfterMs)),
    name(dnsName),
    spkiOf(pub),
    ctx(3, seq(sanExt(dnsName))), // extensions [3] EXPLICIT
  );
  const sig = compactToDerSig(p256.sign(tbs, issuerSk, { prehash: true }));
  const cert = seq(tbs, seq(oid(OID.ecdsaSha256)), bitString(sig));
  return { der: cert, key: { secretKey: sk, publicKey: pub } };
};

/** Sign an ES256 (P-256) compact JWS — header MUST carry `alg:'ES256'` (+ `x5c` for the request). */
export const signEs256Jws = (header, claims, secretKey) => {
  const b64u = (b) => Buffer.from(b).toString('base64url');
  const input = `${b64u(Buffer.from(JSON.stringify(header)))}.${b64u(Buffer.from(JSON.stringify(claims)))}`;
  const sig = p256.sign(new TextEncoder().encode(input), secretKey, { prehash: true, format: 'compact' });
  return `${input}.${b64u(sig)}`;
};

/** DER bytes → standard base64 (x5c entries are base64, not base64url). */
export const derToB64 = (bytes) => Buffer.from(bytes).toString('base64');
