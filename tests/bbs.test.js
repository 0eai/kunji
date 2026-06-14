import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  bbsKeyGen,
  bbsSign,
  bbsVerify,
  bbsDeriveProof,
  bbsVerifyProof,
  bbsBytes,
  bytesToB64u,
  b64uToBytes,
} from '../src/lib/bbs.js';
import { generateMasterKey, deriveBbsHolderSecret } from '../src/lib/crypto/index.js';

describe('deriveBbsHolderSecret (holder binding)', () => {
  it('is 32 bytes, deterministic per (master, issuer), per-issuer, per-master', async () => {
    const master = await generateMasterKey();
    const a = await deriveBbsHolderSecret(master, 'https://issuer.example');
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(32);
    expect(Array.from(await deriveBbsHolderSecret(master, 'https://issuer.example'))).toEqual(Array.from(a)); // deterministic
    expect(Array.from(await deriveBbsHolderSecret(master, 'https://other.example'))).not.toEqual(Array.from(a)); // per-issuer
    const other = await generateMasterKey();
    expect(Array.from(await deriveBbsHolderSecret(other, 'https://issuer.example'))).not.toEqual(Array.from(a)); // per-master
  });
});

// The BBS primitive wrapper (verified-credentials.md §7 v3) over @digitalbazaar/bbs-signatures.

describe('bbs wrapper', () => {
  it('base64url round-trips arbitrary byte lengths', () => {
    for (const n of [0, 1, 2, 3, 16, 31, 32, 80, 96]) {
      const b = new Uint8Array(Array.from({ length: n }, (_, i) => (i * 37 + 5) & 255));
      expect(Array.from(b64uToBytes(bytesToB64u(b)))).toEqual(Array.from(b));
    }
  });

  it('sign → verify; a tampered message rejects', async () => {
    const { secretKey, publicKey } = await bbsKeyGen();
    const header = bbsBytes('hdr');
    const messages = [bbsBytes('a=1'), bbsBytes('b=2')];
    const signature = await bbsSign({ secretKey, publicKey, header, messages });
    expect(await bbsVerify({ publicKey, signature, header, messages })).toBe(true);
    expect(await bbsVerify({ publicKey, signature, header, messages: [bbsBytes('a=1'), bbsBytes('b=9')] })).toBe(false);
  });

  it('deriveProof reveals only disclosed indexes, verifies, and a wrong presentation header rejects', async () => {
    const { secretKey, publicKey } = await bbsKeyGen();
    const header = bbsBytes('hdr');
    const messages = [bbsBytes('a=1'), bbsBytes('b=2'), bbsBytes('c=3')];
    const signature = await bbsSign({ secretKey, publicKey, header, messages });
    const ph = bbsBytes('ph1');
    const disclosedMessageIndexes = [0, 2];
    const disclosedMessages = [messages[0], messages[2]];
    const proof = await bbsDeriveProof({ publicKey, signature, header, messages, presentationHeader: ph, disclosedMessageIndexes });
    expect(await bbsVerifyProof({ publicKey, proof, header, presentationHeader: ph, disclosedMessages, disclosedMessageIndexes })).toBe(true);
    // wrong presentation header (≈ wrong aud/nonce) → reject (replay protection)
    expect(
      await bbsVerifyProof({ publicKey, proof, header, presentationHeader: bbsBytes('ph2'), disclosedMessages, disclosedMessageIndexes }),
    ).toBe(false);
  });

  it('two proofs from ONE signature are unlinkable (differ)', async () => {
    const { secretKey, publicKey } = await bbsKeyGen();
    const header = bbsBytes('hdr');
    const messages = [bbsBytes('a=1'), bbsBytes('b=2')];
    const signature = await bbsSign({ secretKey, publicKey, header, messages });
    const mk = () => bbsDeriveProof({ publicKey, signature, header, messages, presentationHeader: bbsBytes('ph'), disclosedMessageIndexes: [0] });
    expect(bytesToB64u(await mk())).not.toBe(bytesToB64u(await mk()));
  });
});

describe('BBS module parity (wallet lib ↔ demo Node ports are byte-identical)', () => {
  const read = (p) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8');
  for (const f of ['bbs.js', 'vcBbs.js']) {
    it(`${f} is byte-identical across wallet + issuer/node/login demos`, () => {
      const lib = read(`../src/lib/${f}`);
      expect(read(`../examples/kunji-issuer-demo/${f}`)).toBe(lib);
      expect(read(`../examples/kunji-node-demo/${f}`)).toBe(lib);
      expect(read(`../examples/kunji-login-demo/functions/${f}`)).toBe(lib);
    });
  }
});
