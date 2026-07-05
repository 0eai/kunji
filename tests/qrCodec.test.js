import { describe, it, expect } from 'vitest';
import { encodeCompactQr, decodeCompactQr, isCompactQr } from '../src/lib/qrCodec.js';

// Representative login request (base64url-ish session/challenge, like the demo mints).
const base = {
  sessionId: 'Zm9vYmFyc2Vzc2lvbjE2', // ~20 chars
  challenge: 'Y2hhbGxlbmdlLTMyLWJ5dGVzLW9wYXF1ZS10b2tlbg', // ~43 chars
  audience: 'kunji-demo.web.app',
  expiresAt: 1780937741000,
};

describe('qrCodec — K1 compact login QR', () => {
  it('round-trips a plain login request', () => {
    const s = encodeCompactQr(base);
    expect(isCompactQr(s)).toBe(true);
    expect(decodeCompactQr(s)).toEqual({ kunjiAuth: 'v2', ...base });
  });

  it('output is entirely in the QR ALPHANUMERIC charset (so it encodes in alphanumeric mode)', () => {
    const s = encodeCompactQr(base);
    expect(s).toMatch(/^K1:[A-Z2-7]+$/); // K1: prefix + RFC4648 base32 (uppercase, no padding)
    // Belt-and-suspenders: every char must be in the QR alphanumeric set.
    expect(s).toMatch(/^[0-9A-Z $%*+\-./:]+$/);
  });

  it('needs fewer QR data bits than the JSON payload (alphanumeric 5.5 vs byte 8 bits/char)', () => {
    // The win is in QR MODE, not char count: base32 re-expands the payload ~1.6× in characters, but
    // an all-uppercase-alphanumeric string encodes at 5.5 bits/char vs JSON's byte-mode 8 bits/char.
    const rich = { ...base, appName: 'kunji demo' };
    const jsonBits = JSON.stringify({ kunjiAuth: 'v2', ...rich }).length * 8; // byte mode
    const k1Bits = encodeCompactQr(rich).length * 5.5; // alphanumeric mode
    expect(k1Bits).toBeLessThan(jsonBits);
  });

  it('round-trips optional appName, callbackUrl and scope (incl. object scope + lowercase/underscore)', () => {
    const rich = {
      ...base,
      appName: 'Käthe & Co', // non-ascii + symbols survive (they live inside base32)
      callbackUrl: 'https://relay.example.com/cb',
      scope: ['profile', 'vc:age_over_18', { id: 'payments:charge', max: '50USD' }],
    };
    const s = encodeCompactQr(rich);
    expect(s).toMatch(/^K1:[A-Z2-7]+$/); // still alphanumeric despite the rich content
    expect(decodeCompactQr(s)).toEqual({ kunjiAuth: 'v2', ...rich });
  });

  it('omits absent optional fields (no empty keys leak through)', () => {
    const decoded = decodeCompactQr(encodeCompactQr(base));
    expect('appName' in decoded).toBe(false);
    expect('callbackUrl' in decoded).toBe(false);
    expect('scope' in decoded).toBe(false);
  });

  it('drops an empty scope array', () => {
    const decoded = decodeCompactQr(encodeCompactQr({ ...base, scope: [] }));
    expect('scope' in decoded).toBe(false);
  });

  it('rejects malformed input', () => {
    expect(() => decodeCompactQr('not a k1 string')).toThrow();
    expect(() => decodeCompactQr('K1:!!!not-base32!!!')).toThrow();
    expect(isCompactQr('{"kunjiAuth":"v2"}')).toBe(false);
    expect(isCompactQr('')).toBe(false);
    expect(isCompactQr(null)).toBe(false);
  });
});
