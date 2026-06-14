/**
 * Minimal X.509 verification for the OpenID4VP `x509_san_dns` client_id scheme (docs/oid4vc.md §5).
 *
 * SCOPED, deliberately-reduced PKI for a client-only wallet (it cannot run a CA program). This module:
 *   - parses a DER certificate (pure, bounds-checked; rejects BER/indefinite-length and oversized lengths),
 *   - verifies an `x5c` chain: each link's ECDSA-P256-SHA256 signature, the leaf's SAN dNSName == client_id,
 *     the leaf validity window, and that the chain terminates at a PINNED trust anchor (empty ⇒ fail closed),
 *   - verifies the request's ES256 (P-256) JWS with the leaf key.
 *
 * It DOES NOT do full RFC 5280 path validation (BasicConstraints/KeyUsage/EKU/name-constraints/policy),
 * revocation (CRL/OCSP), RSA / non-P256 certs, or wildcard SANs. `@peculiar/x509` is the heavy-dep fallback
 * if a future mandate needs full path validation. Pure + isomorphic over `@noble/curves` p256 + raw bytes,
 * so the demo Node port is byte-identical. No new dependency.
 */
import { p256 } from '@noble/curves/nist.js';

const ECDSA_SHA256_OID = '2a8648ce3d040302'; // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256), DER value bytes
const SAN_OID = '551d11'; // 2.5.29.17 (subjectAltName), DER value bytes

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// Read one DER TLV at `off`. Rejects indefinite-length (BER) and lengths > 4 bytes. Bounds-checked.
const readTLV = (der, off) => {
  if (off + 2 > der.length) throw new Error('der_eof');
  const tag = der[off];
  let len = der[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('der_bad_length'); // 0 ⇒ indefinite (BER); >4 ⇒ absurd
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | der[off + 2 + i];
    hdr = 2 + n;
  }
  const start = off + hdr;
  const end = start + len;
  if (end > der.length || end < start) throw new Error('der_overflow');
  return { tag, start, end, next: end, value: der.subarray(start, end) };
};

// DER ECDSA-Sig-Value SEQUENCE { r INTEGER, s INTEGER } → fixed 64-byte r||s (left-padded). For p256 verify.
const ecdsaDerToCompact = (sigDer) => {
  const seq = readTLV(sigDer, 0);
  if (seq.tag !== 0x30) throw new Error('bad_sig');
  const r = readTLV(sigDer, seq.start);
  const s = readTLV(sigDer, r.next);
  const fix = (tlv) => {
    let v = tlv.value;
    while (v.length > 1 && v[0] === 0) v = v.subarray(1); // strip the INTEGER sign byte
    if (v.length > 32) throw new Error('bad_sig');
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const out = new Uint8Array(64);
  out.set(fix(r), 0);
  out.set(fix(s), 32);
  return out;
};

const parseDerTime = (tlv) => {
  const s = new TextDecoder().decode(tlv.value);
  // UTCTime (tag 0x17) YYMMDDHHMMSSZ; GeneralizedTime (0x18) YYYYMMDDHHMMSSZ.
  const g = tlv.tag === 0x18;
  let year;
  let i;
  if (g) {
    year = Number(s.slice(0, 4));
    i = 4;
  } else {
    const yy = Number(s.slice(0, 2));
    year = yy < 50 ? 2000 + yy : 1900 + yy; // RFC 5280: YY < 50 ⇒ 20YY
    i = 2;
  }
  return Date.UTC(year, Number(s.slice(i, i + 2)) - 1, Number(s.slice(i + 2, i + 4)), Number(s.slice(i + 4, i + 6)), Number(s.slice(i + 6, i + 8)), Number(s.slice(i + 8, i + 10)));
};

// Walk a SubjectAltName extnValue (OCTET STRING → GeneralNames SEQUENCE) collecting dNSName [2] entries.
const sanDnsFromExtnValue = (octet) => {
  const inner = readTLV(octet, 0); // OCTET STRING wraps the GeneralNames DER
  const names = readTLV(octet.subarray(inner.start, inner.end), 0); // SEQUENCE OF GeneralName
  const body = octet.subarray(inner.start, inner.end);
  const out = [];
  let off = names.start;
  while (off < names.end) {
    const gn = readTLV(body, off);
    if (gn.tag === 0x82) out.push(new TextDecoder().decode(gn.value)); // [2] dNSName (IA5String)
    off = gn.next;
  }
  return out;
};

/**
 * Parse a DER X.509 certificate. Returns the bytes needed to verify the chain + identity.
 * @returns {{ tbs: Uint8Array, sigAlgOid: string, signature: Uint8Array, spki: Uint8Array, notBefore: number, notAfter: number, sanDnsNames: string[] }}
 */
export const parseCert = (der) => {
  const cert = readTLV(der, 0);
  if (cert.tag !== 0x30) throw new Error('bad_cert');
  const tbsTlv = readTLV(der, cert.start);
  const tbs = der.subarray(cert.start, tbsTlv.end); // full TBSCertificate TLV — the signed bytes
  const sigAlg = readTLV(der, tbsTlv.next);
  const sigBits = readTLV(der, sigAlg.next); // signatureValue BIT STRING (leading 0x00 = unused bits)
  const signature = sigBits.value.subarray(1);

  // signatureAlgorithm OID (first child of the sigAlg SEQUENCE)
  const sigAlgOidTlv = readTLV(der, sigAlg.start);
  const sigAlgOid = hex(sigAlgOidTlv.value);

  // Walk TBSCertificate: [0] version?, serial, signature, issuer, validity, subject, SPKI, [3] extensions?
  let off = tbsTlv.start;
  let f = readTLV(der, off);
  if (f.tag === 0xa0) off = f.next; // skip explicit version [0]
  f = readTLV(der, off);
  off = f.next; // serialNumber
  f = readTLV(der, off);
  off = f.next; // signature AlgorithmIdentifier
  f = readTLV(der, off);
  off = f.next; // issuer Name
  const validity = readTLV(der, off);
  off = validity.next; // validity SEQUENCE { notBefore, notAfter }
  const nb = readTLV(der, validity.start);
  const na = readTLV(der, nb.next);
  const notBefore = parseDerTime(nb);
  const notAfter = parseDerTime(na);
  f = readTLV(der, off);
  off = f.next; // subject Name
  const spkiTlv = readTLV(der, off);
  off = spkiTlv.next; // SubjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT STRING }
  const spkiAlg = readTLV(der, spkiTlv.start);
  const spkiBits = readTLV(der, spkiAlg.next);
  const spki = spkiBits.value.subarray(1); // the EC point (0x04||X||Y for P-256)

  // extensions [3] EXPLICIT — find SubjectAltName
  let sanDnsNames = [];
  while (off < tbsTlv.end) {
    const ext = readTLV(der, off);
    off = ext.next;
    if (ext.tag === 0xa3) {
      const exts = readTLV(der, ext.start); // SEQUENCE OF Extension
      let eoff = exts.start;
      while (eoff < exts.end) {
        const one = readTLV(der, eoff);
        eoff = one.next;
        const oid = readTLV(der, one.start);
        if (hex(oid.value) === SAN_OID) {
          // after the OID: optional critical BOOLEAN, then the extnValue OCTET STRING
          let p = oid.next;
          let v = readTLV(der, p);
          if (v.tag === 0x01) {
            p = v.next;
            v = readTLV(der, p);
          }
          sanDnsNames = sanDnsFromExtnValue(der.subarray(p, v.end)); // the extnValue OCTET STRING TLV
        }
      }
    }
  }
  return { tbs, sigAlgOid, signature, spki, notBefore, notAfter, sanDnsNames };
};

/** Verify an ES256 (P-256) compact JWS (JOSE r||s signature) against a SEC1 public point. */
export const verifyEs256Jws = (jwt, publicKeyPoint) => {
  const parts = String(jwt).split('.');
  if (parts.length !== 3) return false;
  const input = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const sig = b64uToBytes(parts[2]);
  if (sig.length !== 64) return false; // JOSE ES256 is fixed 64-byte r||s
  try {
    return p256.verify(sig, input, publicKeyPoint, { prehash: true, format: 'compact', lowS: false });
  } catch {
    return false;
  }
};

const b64uToBytes = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
  const bin = atob(t + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Verify an x5c chain (DER-encoded, base64 — leaf first). Checks: SAN dNSName == `dnsName`, the leaf
 * validity window vs `now`, each link's ECDSA-P256-SHA256 signature, and that the top cert is signed by /
 * is a member of `trustAnchors` (an array of DER Uint8Arrays). Empty anchors ⇒ fail closed. ES256-only.
 * @returns {{ ok:true, leafPublicKey: Uint8Array } | { ok:false, error }}
 */
export const verifyX5cChain = ({ x5c, dnsName, trustAnchors = [], now = Date.now() }) => {
  if (!Array.isArray(x5c) || !x5c.length) return { ok: false, error: 'no_x5c' };
  let certs;
  try {
    certs = x5c.map((b64) => parseCert(b64ToBytes(b64)));
  } catch {
    return { ok: false, error: 'bad_cert' };
  }
  const leaf = certs[0];
  if (leaf.sigAlgOid !== ECDSA_SHA256_OID) return { ok: false, error: 'unsupported_cert_alg' };
  if (!leaf.sanDnsNames.includes(dnsName)) return { ok: false, error: 'san_mismatch' };
  if (now < leaf.notBefore || now > leaf.notAfter) return { ok: false, error: 'cert_expired' };

  // verify each link i is signed by i+1's key
  for (let i = 0; i < certs.length - 1; i++) {
    if (!verifyCertSig(certs[i], certs[i + 1].spki)) return { ok: false, error: 'bad_cert_signature' };
  }
  // the chain top must be signed by, or equal to, a pinned trust anchor
  const anchors = (trustAnchors || []).map((d) => parseCert(d instanceof Uint8Array ? d : b64ToBytes(d)));
  const top = certs[certs.length - 1];
  const topIsAnchor = anchors.some((a) => sameBytes(a.spki, top.spki));
  const topSignedByAnchor = anchors.some((a) => a.sigAlgOid === ECDSA_SHA256_OID && verifyCertSig(top, a.spki));
  if (!topIsAnchor && !topSignedByAnchor) return { ok: false, error: 'x5c_untrusted' };
  return { ok: true, leafPublicKey: leaf.spki };
};

const verifyCertSig = (cert, issuerPoint) => {
  if (cert.sigAlgOid !== ECDSA_SHA256_OID) return false;
  try {
    return p256.verify(ecdsaDerToCompact(cert.signature), cert.tbs, issuerPoint, { prehash: true, format: 'compact', lowS: false });
  } catch {
    return false;
  }
};

const b64ToBytes = (b64) => {
  const bin = atob(String(b64).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
