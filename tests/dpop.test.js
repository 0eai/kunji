import { describe, it, expect } from 'vitest';
// DPoP (RFC 9449) sender-constrains the OpenID4VCI access token on the token + credential leg. kunji
// pins EdDSA (not the RFC's usual ES256). These exercise the lib helpers + the issuer demo's binding;
// the full mint-success path is proven by the headless sim (`oid4vc-sim --dpop`).
import { buildDpopProof, verifyDpopProof, jwkThumbprint } from '../src/lib/oid4vc.js';
import { generateEd25519KeyPair } from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';
import { createOffer, handleToken, handleCredential } from '../examples/kunji-issuer-demo/oid4vci.js';

const HTU = 'https://issuer.example/token';
const CREDU = 'https://issuer.example/credential';
const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const kp = () => {
  const k = generateEd25519KeyPair();
  return { sk: k.secretKey, pk: k.publicKey };
};

describe('DPoP proof (RFC 9449, EdDSA-pinned)', () => {
  it('round-trips and returns the RFC 7638 jkt', async () => {
    const { sk, pk } = kp();
    const dpop = await buildDpopProof({ htu: HTU, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk });
    const r = await verifyDpopProof({ dpop, htu: HTU, htm: 'POST' });
    expect(r.ok).toBe(true);
    expect(r.jkt).toBe(await jwkThumbprint(okpJwk(pk)));
  });

  it('binds the access token via `ath` (a mismatch is rejected)', async () => {
    const { sk, pk } = kp();
    const dpop = await buildDpopProof({ htu: HTU, htm: 'POST', accessToken: 'tok-1', holderSecretKey: sk, holderPublicKey: pk });
    expect((await verifyDpopProof({ dpop, htu: HTU, htm: 'POST', accessToken: 'tok-1' })).ok).toBe(true);
    expect(await verifyDpopProof({ dpop, htu: HTU, htm: 'POST', accessToken: 'tok-2' })).toMatchObject({ ok: false, error: 'dpop_ath_mismatch' });
  });

  it('rejects htu / htm mismatch; ignores query+fragment in htu', async () => {
    const { sk, pk } = kp();
    const dpop = await buildDpopProof({ htu: `${HTU}?x=1#f`, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk });
    expect((await verifyDpopProof({ dpop, htu: HTU, htm: 'POST' })).ok).toBe(true); // query/fragment stripped
    expect(await verifyDpopProof({ dpop, htu: CREDU, htm: 'POST' })).toMatchObject({ ok: false, error: 'dpop_htu_mismatch' });
    expect(await verifyDpopProof({ dpop, htu: HTU, htm: 'GET' })).toMatchObject({ ok: false, error: 'dpop_htm_mismatch' });
  });

  it('rejects a tampered signature, a stale proof, and a non-JWT', async () => {
    const { sk, pk } = kp();
    const dpop = await buildDpopProof({ htu: HTU, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk });
    const dot = dpop.lastIndexOf('.');
    const sig = dpop.slice(dot + 1);
    const forged = dpop.slice(0, dot + 1) + (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    expect(await verifyDpopProof({ dpop: forged, htu: HTU, htm: 'POST' })).toMatchObject({ ok: false, error: 'bad_dpop_signature' });
    const stale = await buildDpopProof({ htu: HTU, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk, now: Date.now() - 10 * 60 * 1000 });
    expect(await verifyDpopProof({ dpop: stale, htu: HTU, htm: 'POST' })).toMatchObject({ ok: false, error: 'stale_dpop' });
    expect(await verifyDpopProof({ dpop: 'not-a-jwt', htu: HTU, htm: 'POST' })).toMatchObject({ ok: false, error: 'malformed_dpop' });
  });

  it('jkt is stable per key; jti is fresh per proof (binding vs replay are separate handles)', async () => {
    const { sk, pk } = kp();
    const a = await verifyDpopProof({ dpop: await buildDpopProof({ htu: HTU, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk }), htu: HTU, htm: 'POST' });
    const b = await verifyDpopProof({ dpop: await buildDpopProof({ htu: HTU, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk }), htu: HTU, htm: 'POST' });
    expect(a.jkt).toBe(b.jkt);
    expect(a.jti).not.toBe(b.jti);
  });
});

describe('DPoP at the issuer demo (token binding + back-compat)', () => {
  const offerCode = () => createOffer().offer.grants[PRE_AUTH]['pre-authorized_code'];

  it('no DPoP header → a bearer token (back-compat, unchanged)', async () => {
    const r = await handleToken({ grant_type: PRE_AUTH, 'pre-authorized_code': offerCode() });
    expect(r.json.token_type).toBe('bearer');
  });

  it('DPoP at /token → a DPoP-bound token, and /credential enforces the jkt', async () => {
    const { sk, pk } = kp();
    const tokDpop = await buildDpopProof({ htu: HTU, htm: 'POST', holderSecretKey: sk, holderPublicKey: pk });
    const tr = await handleToken({ grant_type: PRE_AUTH, 'pre-authorized_code': offerCode() }, { dpop: tokDpop, htu: HTU });
    expect(tr.json.token_type).toBe('DPoP');
    const access = tr.json.access_token;

    // a bound token with NO DPoP proof at /credential → rejected (before any mint)
    const miss = await handleCredential({ authorization: `DPoP ${access}`, htu: CREDU, body: { proof: { proof_type: 'jwt', jwt: 'x' } } });
    expect(miss.status).toBe(401);

    // a DPoP proof signed by a DIFFERENT key → jkt mismatch (before any mint)
    const evil = kp();
    const evilProof = await buildDpopProof({ htu: CREDU, htm: 'POST', accessToken: access, holderSecretKey: evil.sk, holderPublicKey: evil.pk });
    const wrong = await handleCredential({ authorization: `DPoP ${access}`, dpop: evilProof, htu: CREDU, body: { proof: { proof_type: 'jwt', jwt: 'x' } } });
    expect(wrong.json.detail).toBe('dpop_jkt_mismatch');
  });
});
