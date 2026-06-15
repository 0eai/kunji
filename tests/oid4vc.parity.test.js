import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// The OpenID4VC envelope, like vc.js, has a canonical wallet copy (src/lib, async subtle digest under
// the hood) and a Node port shipped in the demos (sync). They must interop byte-for-byte across the
// proof JWT and the vp_token, and the demo copies must stay identical — same guard as vc.parity.
import {
  buildProofJwt as libBuildProof,
  verifyProofJwt as libVerifyProof,
  buildVpToken as libBuildVp,
  verifyVpToken as libVerifyVp,
  buildPresentationDefinition,
  buildDcqlQuery,
  buildVpResponse as libBuildVpResponse,
  buildSignedAuthorizationRequest as libBuildSignedReq,
  verifyRequestObject as libVerifyReq,
  buildDpopProof as libBuildDpop,
  verifyDpopProof as libVerifyDpop,
  jwkThumbprint as libThumbprint,
  computeCodeChallenge as libChallenge,
  verifyPkce as libVerifyPkce,
} from '../src/lib/oid4vc.js';
import {
  buildProofJwt as nodeBuildProof,
  verifyProofJwt as nodeVerifyProof,
  buildVpToken as nodeBuildVp,
  verifyVpToken as nodeVerifyVp,
  buildVpResponse as nodeBuildVpResponse,
  buildSignedAuthorizationRequest as nodeBuildSignedReq,
  verifyRequestObject as nodeVerifyReq,
  buildDpopProof as nodeBuildDpop,
  verifyDpopProof as nodeVerifyDpop,
  jwkThumbprint as nodeThumbprint,
  computeCodeChallenge as nodeChallenge,
  verifyPkce as nodeVerifyPkce,
} from '../examples/kunji-node-demo/oid4vc.js';
import { mintCredential as nodeMint } from '../examples/kunji-node-demo/vc.js';
import { generateEd25519KeyPair } from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';

const ISS = 'https://issuer.example';
const KID = 'k1';
const CLIENT = 'verifier.example';
const NONCE = 'n'.repeat(24);

describe('OpenID4VC parity (wallet lib ↔ demo Node port)', () => {
  const ctx = () => {
    const issuer = generateEd25519KeyPair();
    const holder = generateEd25519KeyPair();
    const sdjwt = nodeMint(issuer.secretKey, {
      kid: KID,
      iss: ISS,
      vct: 'age',
      claims: { age_over_18: true },
      holderJwk: okpJwk(holder.publicKey),
      ttlSeconds: 3600,
    });
    const getIssuerKeys = async () => [{ ...okpJwk(issuer.publicKey), kid: KID }];
    const pd = buildPresentationDefinition({ vct: 'age', disclose: ['age_over_18'] });
    return { holder, sdjwt, getIssuerKeys, pd };
  };

  it('proof JWT: lib builds → Node verifies, and the reverse', () => {
    const h = generateEd25519KeyPair();
    const args = { holderSecretKey: h.secretKey, holderPublicKey: h.publicKey, audience: ISS, cNonce: 'cn' };
    expect(nodeVerifyProof({ proofJwt: libBuildProof(args), audience: ISS, cNonce: 'cn' }).ok).toBe(true);
    expect(libVerifyProof({ proofJwt: nodeBuildProof(args), audience: ISS, cNonce: 'cn' }).ok).toBe(true);
  });

  it('DPoP: lib builds → Node verifies, and the reverse (with an identical jkt)', async () => {
    const h = generateEd25519KeyPair();
    const args = { htu: 'https://issuer.example/token', htm: 'POST', holderSecretKey: h.secretKey, holderPublicKey: h.publicKey };
    const libDpop = await libBuildDpop(args);
    const nodeDpop = await nodeBuildDpop(args);
    const a = await nodeVerifyDpop({ dpop: libDpop, htu: args.htu, htm: 'POST' });
    const b = await libVerifyDpop({ dpop: nodeDpop, htu: args.htu, htm: 'POST' });
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    // both implementations compute the same RFC 7638 thumbprint for the same key
    expect(a.jkt).toBe(await libThumbprint(okpJwk(h.publicKey)));
    expect(await nodeThumbprint(okpJwk(h.publicKey))).toBe(await libThumbprint(okpJwk(h.publicKey)));
  });

  it('PKCE: lib challenge verifies under Node verifyPkce, and the reverse (S256 identical)', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await libChallenge(verifier)).toBe(await nodeChallenge(verifier)); // byte-identical S256
    const libCc = await libChallenge(verifier);
    expect(await nodeVerifyPkce({ codeVerifier: verifier, codeChallenge: libCc })).toBe(true);
    const nodeCc = await nodeChallenge(verifier);
    expect(await libVerifyPkce({ codeVerifier: verifier, codeChallenge: nodeCc })).toBe(true);
  });

  it('vp_token: Node presents → lib verifies', async () => {
    const { holder, sdjwt, getIssuerKeys, pd } = ctx();
    const vpToken = nodeBuildVp({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const r = await libVerifyVp({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, iss: ISS, vct: 'age', claims: { age_over_18: true } });
  });

  it('vp_token: lib presents → Node verifies (reverse direction)', async () => {
    const { holder, sdjwt, getIssuerKeys, pd } = ctx();
    const vpToken = await libBuildVp({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const r = await nodeVerifyVp({ vpToken, presentationDefinition: pd, getIssuerKeys, clientId: CLIENT, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, iss: ISS, vct: 'age', claims: { age_over_18: true } });
  });

  it('signed request: lib signs → Node verifies, and the reverse', async () => {
    const v = generateEd25519KeyPair();
    const getVerifierKeys = async () => [{ ...okpJwk(v.publicKey), kid: 'vk' }];
    const params = { client_id: 'https://v.example', response_type: 'vp_token', response_uri: 'https://v.example/r', nonce: NONCE, state: 's' };
    const libJwt = libBuildSignedReq(v.secretKey, { kid: 'vk', params });
    expect((await nodeVerifyReq({ requestJwt: libJwt, getVerifierKeys, clientId: 'https://v.example' })).ok).toBe(true);
    const nodeJwt = nodeBuildSignedReq(v.secretKey, { kid: 'vk', params });
    expect((await libVerifyReq({ requestJwt: nodeJwt, getVerifierKeys, clientId: 'https://v.example' })).ok).toBe(true);
  });

  it('DCQL: Node builds the keyed response → lib verifies (and reverse)', async () => {
    const { holder, sdjwt, getIssuerKeys } = ctx();
    const dcqlQuery = buildDcqlQuery({ id: 'c', vct: 'age', disclose: ['age_over_18'] });
    const request = { dcqlQuery, clientId: CLIENT, nonce: NONCE, state: 's' };
    const present = await libBuildVp({ sdjwt, disclose: ['age_over_18'], clientId: CLIENT, nonce: NONCE, holderSecretKey: holder.secretKey });
    const nodeBody = nodeBuildVpResponse({ request, presentation: present });
    expect(await libVerifyVp({ vpToken: nodeBody.vp_token, dcqlQuery, getIssuerKeys, clientId: CLIENT, nonce: NONCE })).toMatchObject({ ok: true, claims: { age_over_18: true } });
    const libBody = libBuildVpResponse({ request, presentation: present });
    expect(await nodeVerifyVp({ vpToken: libBody.vp_token, dcqlQuery, getIssuerKeys, clientId: CLIENT, nonce: NONCE })).toMatchObject({ ok: true, claims: { age_over_18: true } });
  });

  it('the demo oid4vc.js copies are byte-identical', () => {
    const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
    const node = read('../examples/kunji-node-demo/oid4vc.js');
    expect(read('../examples/kunji-issuer-demo/oid4vc.js')).toBe(node);
    // kunji-demo.web.app (the deployed RP) also runs this port for its live issuer + verifier.
    expect(read('../examples/kunji-login-demo/functions/oid4vc.js')).toBe(node);
    // issuer.kunji.cc (the real issuer) ships the same Node port.
    expect(read('../issuer-functions/oid4vc.js')).toBe(node);
  });
});
