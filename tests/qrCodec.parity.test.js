import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// issuer-web is deliberately isolated from wallet imports (CLAUDE.md), so it carries a byte-equal COPY
// of the login-QR codec. Guard that the copy never drifts from the wallet's source of truth — same
// pattern as vc.parity / oid4vc.parity.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('qrCodec parity — issuer-web copy === wallet source', () => {
  it('issuer-web/src/qrCodec.js is byte-identical to src/lib/qrCodec.js', () => {
    const canonical = readFileSync(resolve(root, 'src/lib/qrCodec.js'), 'utf8');
    const copy = readFileSync(resolve(root, 'issuer-web/src/qrCodec.js'), 'utf8');
    expect(copy).toBe(canonical);
  });
});
