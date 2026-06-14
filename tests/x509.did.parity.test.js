import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// x509.js and did.js are pure (@noble/curves p256 + raw bytes / atob + fetch), so the demo Node ports are
// byte-identical to the wallet copies — the jwe.js parity guard. Cross-interop is covered by
// oid4vc.x509.test.js / oid4vc.did.test.js (both drive verifyRequestObject through these modules).
const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

describe('x509.js / did.js byte-parity (wallet ↔ demo port)', () => {
  it('the demo x509.js is byte-identical to src/lib/x509.js', () => {
    expect(read('../examples/kunji-node-demo/x509.js')).toBe(read('../src/lib/x509.js'));
  });
  it('the demo did.js is byte-identical to src/lib/did.js', () => {
    expect(read('../examples/kunji-node-demo/did.js')).toBe(read('../src/lib/did.js'));
  });
});
