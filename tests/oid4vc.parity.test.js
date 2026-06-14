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
} from '../src/lib/oid4vc.js';
import {
  buildProofJwt as nodeBuildProof,
  verifyProofJwt as nodeVerifyProof,
  buildVpToken as nodeBuildVp,
  verifyVpToken as nodeVerifyVp,
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

  it('the demo oid4vc.js copies are byte-identical', () => {
    const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
    const node = read('../examples/kunji-node-demo/oid4vc.js');
    expect(read('../examples/kunji-issuer-demo/oid4vc.js')).toBe(node);
  });
});
