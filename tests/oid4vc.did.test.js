import { describe, it, expect } from 'vitest';
// The OpenID4VP `did` client_id scheme: a signed (EdDSA) request whose key is resolved from the DID —
// `did:jwk` (embedded, no fetch) or `did:web` (fetched did.json). verifyRequestObject resolves the key via
// the injected resolveDidKey, then verifies with the existing EdDSA path.
import { buildSignedAuthorizationRequest, verifyRequestObject } from '../src/lib/oid4vc.js';
import { resolveDidKey, parseDidJwk, didWebToUrl } from '../src/lib/did.js';
import { generateEd25519KeyPair } from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';

const NONCE = 'n'.repeat(24);
const didJwkOf = (pub) => `did:jwk:${Buffer.from(JSON.stringify(okpJwk(pub))).toString('base64url')}`;
const jar = (sk, clientId, kid) => buildSignedAuthorizationRequest(sk, { kid, params: { client_id: clientId, response_type: 'vp_token', nonce: NONCE, response_uri: 'https://x/r' } });

describe('did helpers', () => {
  it('parseDidJwk round-trips a JWK; didWebToUrl maps host[:path]', () => {
    const v = generateEd25519KeyPair();
    expect(parseDidJwk(didJwkOf(v.publicKey))).toEqual(okpJwk(v.publicKey));
    expect(didWebToUrl('did:web:verifier.example')).toBe('https://verifier.example/.well-known/did.json');
    expect(didWebToUrl('did:web:verifier.example:vc:1')).toBe('https://verifier.example/vc/1/did.json');
    expect(() => parseDidJwk('did:web:x')).toThrow();
  });
});

describe('OpenID4VP did:jwk request verification', () => {
  it('verifies a request signed by the embedded key', async () => {
    const v = generateEd25519KeyPair();
    const did = didJwkOf(v.publicKey);
    const r = await verifyRequestObject({ requestJwt: jar(v.secretKey, did), resolveDidKey, clientId: did });
    expect(r).toMatchObject({ ok: true, scheme: 'did', clientId: did });
  });

  it('rejects when the signer differs from the embedded key (key/clientId tamper)', async () => {
    const a = generateEd25519KeyPair();
    const b = generateEd25519KeyPair();
    const did = didJwkOf(a.publicKey); // advertises a's key…
    const r = await verifyRequestObject({ requestJwt: jar(b.secretKey, did), resolveDidKey, clientId: did }); // …but b signed
    expect(r).toMatchObject({ ok: false, error: 'bad_request_signature' });
  });

  it('rejects when no DID resolver is injected', async () => {
    const v = generateEd25519KeyPair();
    const did = didJwkOf(v.publicKey);
    expect(await verifyRequestObject({ requestJwt: jar(v.secretKey, did), clientId: did })).toMatchObject({ ok: false, error: 'unsupported_client_id_scheme' });
  });
});

describe('OpenID4VP did:web request verification', () => {
  const DID = 'did:web:verifier.example';
  const stubResolver = (doc, ok = true) => (did, opts) =>
    resolveDidKey(did, { ...opts, fetchImpl: async () => ({ ok, json: async () => doc }) });

  it('fetches the did.json and verifies by kid', async () => {
    const v = generateEd25519KeyPair();
    const doc = { verificationMethod: [{ id: `${DID}#key-1`, type: 'JsonWebKey2020', publicKeyJwk: okpJwk(v.publicKey) }] };
    const r = await verifyRequestObject({ requestJwt: jar(v.secretKey, DID, 'key-1'), resolveDidKey: stubResolver(doc), clientId: DID });
    expect(r).toMatchObject({ ok: true, scheme: 'did' });
  });

  it('rejects a wrong published key and an unreachable did.json', async () => {
    const v = generateEd25519KeyPair();
    const other = generateEd25519KeyPair();
    const wrongDoc = { verificationMethod: [{ id: `${DID}#key-1`, publicKeyJwk: okpJwk(other.publicKey) }] };
    expect(await verifyRequestObject({ requestJwt: jar(v.secretKey, DID, 'key-1'), resolveDidKey: stubResolver(wrongDoc), clientId: DID })).toMatchObject({ ok: false, error: 'bad_request_signature' });
    expect(await verifyRequestObject({ requestJwt: jar(v.secretKey, DID, 'key-1'), resolveDidKey: stubResolver({}, false), clientId: DID })).toMatchObject({ ok: false, error: 'did_unresolved' });
  });
});
