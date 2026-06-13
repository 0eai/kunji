import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// Canonical wallet/holder lib (src/lib, async subtle digest) ↔ the demos' Node port (sync
// node:crypto digest). They must interop byte-for-byte across mint/present/verify, the way
// capability.parity.test.js guards the capability verifier.
import {
  mintCredential as libMint,
  buildPresentation as libPresent,
  verifyCredentialPresentation as libVerify,
} from '../src/lib/vc.js';
import {
  mintCredential as nodeMint,
  buildPresentation as nodePresent,
  verifyCredentialPresentation as nodeVerify,
} from '../examples/kunji-node-demo/vc.js';
import {
  generateEd25519KeyPair,
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveECDHSharedSecret,
  encryptData,
  decryptData,
} from '../src/lib/crypto/index.js';
import { okpJwk } from '../src/lib/capability.js';

const ISS = 'https://issuer.example';
const VCT = 'https://issuer.example/age';
const KID = 'k1';
const AUD = 'rp.example.com';
const NONCE = 'n'.repeat(64);

describe('VC parity (wallet lib ↔ demo Node port)', () => {
  const ctx = () => {
    const issuer = generateEd25519KeyPair();
    const holder = generateEd25519KeyPair();
    const holderJwk = okpJwk(holder.publicKey);
    const getIssuerKeys = async () => [{ ...okpJwk(issuer.publicKey), kid: KID }];
    const mintArgs = { kid: KID, iss: ISS, vct: VCT, claims: { age_over_18: true }, holderJwk, ttlSeconds: 3600 };
    return { issuer, holder, getIssuerKeys, mintArgs };
  };

  it('Node-issuer mint → wallet present → Node-RP verify', async () => {
    const { issuer, holder, getIssuerKeys, mintArgs } = ctx();
    const credential = nodeMint(issuer.secretKey, mintArgs);
    const presentation = await libPresent({
      sdjwt: credential,
      disclose: ['age_over_18'],
      audience: AUD,
      nonce: NONCE,
      holderSecretKey: holder.secretKey,
    });
    const r = await nodeVerify({ presentation, getIssuerKeys, checkStatus: async () => true, audience: AUD, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, iss: ISS, vct: VCT, claims: { age_over_18: true } });
  });

  it('wallet-lib mint → Node present → wallet-lib verify (reverse direction)', async () => {
    const { issuer, holder, getIssuerKeys, mintArgs } = ctx();
    const credential = await libMint(issuer.secretKey, mintArgs);
    const presentation = nodePresent({
      sdjwt: credential,
      disclose: ['age_over_18'],
      audience: AUD,
      nonce: NONCE,
      holderSecretKey: holder.secretKey,
    });
    const r = await libVerify({ presentation, getIssuerKeys, checkStatus: async () => true, audience: AUD, nonce: NONCE });
    expect(r).toMatchObject({ ok: true, iss: ISS, vct: VCT, claims: { age_over_18: true } });
  });

  // The two demos ship their own copy of the Node VC port (self-contained, no shared import path) —
  // guard that they stay byte-identical, the way the capability verifier copies are guarded.
  it('all Node vc.js copies are byte-identical', () => {
    const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
    const node = read('../examples/kunji-node-demo/vc.js');
    expect(read('../examples/kunji-issuer-demo/vc.js')).toBe(node);
    expect(read('../examples/kunji-login-demo/functions/vc.js')).toBe(node);
  });

  it('issuer → wallet credential relay: ECDH-encrypt then decrypt round-trips the SD-JWT', async () => {
    // Wallet leaves a transport key; issuer ECDH-encrypts to it and deposits; wallet decrypts.
    const wallet = await generateECDHKeyPair();
    const transportPub = await exportECDHPublicKey(wallet.publicKey);
    const issuer = await generateECDHKeyPair();
    const issuerPubE = await exportECDHPublicKey(issuer.publicKey);
    const sdjwt = 'header.payload.sig~disclosure~';
    const sharedIssuer = await deriveECDHSharedSecret(issuer.privateKey, await importECDHPublicKey(transportPub));
    const encryptedCredential = await encryptData(sdjwt, sharedIssuer);
    const sharedWallet = await deriveECDHSharedSecret(wallet.privateKey, await importECDHPublicKey(issuerPubE));
    expect(await decryptData(encryptedCredential, sharedWallet)).toBe(sdjwt);
  });
});
