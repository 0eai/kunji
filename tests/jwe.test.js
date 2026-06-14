import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// The OID4VP encrypted-response JWE (ECDH-ES + A256GCM, compact) has a canonical wallet copy
// (src/lib/jwe.js) and a byte-identical Node port shipped in the demos. They must interop in both
// directions (wallet encrypts → demo decrypts and the reverse), and the demo copy must stay identical
// — same parity guard as vc.js / oid4vc.js.
import { encryptJwe as libEncrypt, decryptJwe as libDecrypt, generateJweKeyPair as libGen } from '../src/lib/jwe.js';
import {
  encryptJwe as nodeEncrypt,
  decryptJwe as nodeDecrypt,
  generateJweKeyPair as nodeGen,
} from '../examples/kunji-node-demo/jwe.js';

const PAYLOAD = { vp_token: 'eyJ.payload.kbjwt', state: 'st-123', nested: { a: 1, b: [2, 3] } };

describe('JWE ECDH-ES / A256GCM (OID4VP encrypted response)', () => {
  it('round-trips an object and produces compact 5-part serialization with an empty encrypted_key', async () => {
    const { publicJwk, privateJwk } = await libGen();
    const jwe = await libEncrypt(PAYLOAD, publicJwk);
    const parts = jwe.split('.');
    expect(parts).toHaveLength(5);
    expect(parts[1]).toBe(''); // ECDH-ES direct: no wrapped CEK
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    expect(header).toMatchObject({ alg: 'ECDH-ES', enc: 'A256GCM' });
    expect(header.epk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(await libDecrypt(jwe, privateJwk)).toEqual(PAYLOAD);
  });

  it('is non-deterministic (fresh ephemeral key + iv per call)', async () => {
    const { publicJwk } = await libGen();
    expect(await libEncrypt(PAYLOAD, publicJwk)).not.toBe(await libEncrypt(PAYLOAD, publicJwk));
  });

  it('rejects decryption with the wrong recipient key', async () => {
    const a = await libGen();
    const b = await libGen();
    const jwe = await libEncrypt(PAYLOAD, a.publicJwk);
    await expect(libDecrypt(jwe, b.privateJwk)).rejects.toThrow();
  });

  it('rejects a tampered ciphertext (AEAD tag)', async () => {
    const { publicJwk, privateJwk } = await libGen();
    const jwe = await libEncrypt(PAYLOAD, publicJwk);
    const parts = jwe.split('.');
    const ct = parts[3];
    parts[3] = (ct[0] === 'A' ? 'B' : 'A') + ct.slice(1); // flip a data bit in the ciphertext
    await expect(libDecrypt(parts.join('.'), privateJwk)).rejects.toThrow();
  });

  it('parity: wallet encrypts → demo decrypts, and the reverse', async () => {
    const libKp = await libGen();
    const jweFromLib = await libEncrypt(PAYLOAD, libKp.publicJwk);
    expect(await nodeDecrypt(jweFromLib, libKp.privateJwk)).toEqual(PAYLOAD);

    const nodeKp = await nodeGen();
    const jweFromNode = await nodeEncrypt(PAYLOAD, nodeKp.publicJwk);
    expect(await libDecrypt(jweFromNode, nodeKp.privateJwk)).toEqual(PAYLOAD);
  });

  it('the demo jwe.js copy is byte-identical to src/lib/jwe.js', () => {
    const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
    expect(read('../examples/kunji-node-demo/jwe.js')).toBe(read('../src/lib/jwe.js'));
  });
});
