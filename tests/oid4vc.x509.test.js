import { describe, it, expect } from 'vitest';
// The OpenID4VP `x509_san_dns` client_id scheme: a signed request (ES256 JWS) carries an x5c chain; the
// wallet verifies the chain (SAN == client_id, validity, ECDSA-P256-SHA256 to a PINNED anchor — scoped,
// see docs/oid4vc.md) then the JWS with the leaf key. verifyRequestObject delegates x509 to an injected
// verifier so the EdDSA-pure envelope never imports the DER parser.
import { verifyRequestObject, parseClientIdScheme } from '../src/lib/oid4vc.js';
import { verifyX5cChain, verifyEs256Jws } from '../src/lib/x509.js';
import { mintCert, signEs256Jws, derToB64 } from '../examples/kunji-node-demo/x509-mint.js';

const DNS = 'verifier.example';
const CID = `x509_san_dns:${DNS}`;
const now = () => Date.now();

// Mirror the wallet's verifyVerifierX509 (without importing the firebase-coupled service).
const verifyX509 = async ({ requestJwt, x5c, dnsName, trustAnchors, now: t }) => {
  const chain = verifyX5cChain({ x5c, dnsName, trustAnchors, now: t });
  if (!chain.ok) return chain;
  if (!verifyEs256Jws(requestJwt, chain.leafPublicKey)) return { ok: false, error: 'bad_request_signature' };
  return { ok: true };
};

const claims = () => ({ client_id: CID, response_type: 'vp_token', nonce: 'n'.repeat(24), iat: Math.floor(now() / 1000), exp: Math.floor(now() / 1000) + 300 });
const req = (x5c, key) => signEs256Jws({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c }, claims(), key.secretKey);

describe('parseClientIdScheme', () => {
  it('classifies the schemes', () => {
    expect(parseClientIdScheme('https://verifier.example').scheme).toBe('https');
    expect(parseClientIdScheme('verifier.example').scheme).toBe('https'); // bare origin = default
    expect(parseClientIdScheme(CID)).toEqual({ scheme: 'x509_san_dns', value: DNS });
    expect(parseClientIdScheme('did:web:verifier.example').scheme).toBe('did');
    expect(parseClientIdScheme('did:jwk:eyJ').scheme).toBe('did');
  });
});

describe('OpenID4VP x509_san_dns request verification', () => {
  it('verifies a CA→leaf chain anchored at the CA', async () => {
    const ca = mintCert({ dnsName: 'ca.example' });
    const leaf = mintCert({ dnsName: DNS, issuerKey: ca.key, issuerDns: 'ca.example' });
    const x5c = [derToB64(leaf.der), derToB64(ca.der)];
    const r = await verifyRequestObject({ requestJwt: req(x5c, leaf.key), verifyX509, trustAnchors: [ca.der], clientId: CID });
    expect(r).toMatchObject({ ok: true, scheme: 'x509_san_dns', clientId: CID });
  });

  it('fails closed with NO trust anchors (the shipped wallet default)', async () => {
    const leaf = mintCert({ dnsName: DNS });
    const r = await verifyRequestObject({ requestJwt: req([derToB64(leaf.der)], leaf.key), verifyX509, trustAnchors: [], clientId: CID });
    expect(r).toMatchObject({ ok: false, error: 'x5c_untrusted' });
  });

  it('rejects a SAN that does not match the client_id', async () => {
    const leaf = mintCert({ dnsName: 'evil.example' }); // SAN ≠ client_id DNS
    const r = await verifyRequestObject({ requestJwt: req([derToB64(leaf.der)], leaf.key), verifyX509, trustAnchors: [leaf.der], clientId: CID });
    expect(r).toMatchObject({ ok: false, error: 'san_mismatch' });
  });

  it('rejects a tampered leaf cert (CA-signed) and a tampered JWS signature', async () => {
    const ca = mintCert({ dnsName: 'ca.example' });
    const leaf = mintCert({ dnsName: DNS, issuerKey: ca.key, issuerDns: 'ca.example' });
    // tamper a leaf byte → the CA's signature over the leaf no longer verifies (leaf isn't the anchor)
    const badLeaf = Uint8Array.from(leaf.der);
    badLeaf[badLeaf.length - 4] ^= 0x01;
    const rCert = await verifyRequestObject({ requestJwt: req([derToB64(badLeaf), derToB64(ca.der)], leaf.key), verifyX509, trustAnchors: [ca.der], clientId: CID });
    expect(rCert).toMatchObject({ ok: false, error: 'bad_cert_signature' });
    // tamper the JWS signature → ES256 verify fails (the genuine chain still trusts the leaf key)
    const jwt = req([derToB64(leaf.der), derToB64(ca.der)], leaf.key);
    const dot = jwt.lastIndexOf('.');
    const sig = jwt.slice(dot + 1);
    const forged = jwt.slice(0, dot + 1) + (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const rSig = await verifyRequestObject({ requestJwt: forged, verifyX509, trustAnchors: [ca.der], clientId: CID });
    expect(rSig).toMatchObject({ ok: false, error: 'bad_request_signature' });
  });

  it('rejects an expired leaf certificate', async () => {
    const leaf = mintCert({ dnsName: DNS, notBeforeMs: Date.now() - 7200_000, notAfterMs: Date.now() - 3600_000 });
    const r = await verifyRequestObject({ requestJwt: req([derToB64(leaf.der)], leaf.key), verifyX509, trustAnchors: [leaf.der], clientId: CID });
    expect(r).toMatchObject({ ok: false, error: 'cert_expired' });
  });

  it('rejects a non-ES256 alg and a missing x509 verifier', async () => {
    const leaf = mintCert({ dnsName: DNS });
    const x5c = [derToB64(leaf.der)];
    // no verifyX509 injected → unsupported scheme
    expect(await verifyRequestObject({ requestJwt: req(x5c, leaf.key), trustAnchors: [leaf.der], clientId: CID })).toMatchObject({ ok: false, error: 'unsupported_client_id_scheme' });
    // an EdDSA-headed JWS for an x509 client_id → bad header
    const eddsaHeaded = signEs256Jws({ alg: 'EdDSA', typ: 'oauth-authz-req+jwt', x5c }, claims(), leaf.key.secretKey);
    expect(await verifyRequestObject({ requestJwt: eddsaHeaded, verifyX509, trustAnchors: [leaf.der], clientId: CID })).toMatchObject({ ok: false, error: 'bad_request_header' });
  });
});
