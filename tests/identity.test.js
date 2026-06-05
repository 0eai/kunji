import { describe, it, expect, vi } from 'vitest';

// identity.js pulls in Firebase at import; stub it so these pure validators run in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('../src/services/activityLog', () => ({
  logActivity: vi.fn(),
  listenToActivityLog: vi.fn(),
}));

import {
  parseQRPayload,
  isSafeReturnUrl,
  deriveSubFromPublicKey,
  requestsProfile,
} from '../src/services/identity.js';

const validQR = (over = {}) =>
  JSON.stringify({
    kunjiAuth: 'v2',
    mode: 'discoverable',
    sessionId: 's',
    challenge: 'c',
    audience: 'app.com',
    callbackUrl: 'https://app.com/kunji/callback',
    expiresAt: Date.now() + 60_000,
    ...over,
  });

describe('deriveSubFromPublicKey', () => {
  it('is 64-hex, deterministic, and distinct per key', async () => {
    const a = await deriveSubFromPublicKey('AAAA');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await deriveSubFromPublicKey('AAAA')).toBe(a);
    expect(await deriveSubFromPublicKey('BBBB')).not.toBe(a);
  });
});

describe('parseQRPayload', () => {
  it('accepts a valid v2 payload', () => {
    expect(parseQRPayload(validQR()).audience).toBe('app.com');
  });

  it('accepts a same-site subdomain callback', () => {
    expect(() => parseQRPayload(validQR({ callbackUrl: 'https://api.app.com/cb' }))).not.toThrow();
  });

  it('derives the same-site callback when the lean QR omits it', () => {
    const parsed = parseQRPayload(validQR({ callbackUrl: undefined }));
    expect(parsed.callbackUrl).toBe('https://app.com/kunji/callback');
  });

  it('parses a lean QR without mode (defaults to discoverable)', () => {
    expect(() => parseQRPayload(validQR({ mode: undefined }))).not.toThrow();
  });

  it('rejects a non-discoverable mode when present', () => {
    expect(() => parseQRPayload(validQR({ mode: 'pre-registered' }))).toThrow('invalid_qr');
  });

  it('still parses a full QR with explicit mode + callbackUrl (backward compatible)', () => {
    expect(parseQRPayload(validQR()).callbackUrl).toBe('https://app.com/kunji/callback');
  });

  it('rejects non-JSON', () => {
    expect(() => parseQRPayload('not json')).toThrow('invalid_qr');
  });

  it('rejects a payload missing required fields', () => {
    expect(() => parseQRPayload(JSON.stringify({ kunjiAuth: 'v2', mode: 'discoverable' }))).toThrow(
      'invalid_qr',
    );
  });

  it('rejects an expired QR', () => {
    expect(() => parseQRPayload(validQR({ expiresAt: Date.now() - 1 }))).toThrow('expired_qr');
  });

  it('accepts an optional scope array and flags a profile request', () => {
    const parsed = parseQRPayload(validQR({ scope: ['profile'] }));
    expect(parsed.scope).toEqual(['profile']);
    expect(requestsProfile(parsed)).toBe(true);
  });

  it('treats a missing scope as no profile request', () => {
    expect(requestsProfile(parseQRPayload(validQR()))).toBe(false);
  });

  it('rejects a malformed scope (not an array of strings)', () => {
    expect(() => parseQRPayload(validQR({ scope: 'profile' }))).toThrow('invalid_qr');
    expect(() => parseQRPayload(validQR({ scope: [1, 2] }))).toThrow('invalid_qr');
  });

  it('rejects a cross-site callback', () => {
    expect(() => parseQRPayload(validQR({ callbackUrl: 'https://evil.com/cb' }))).toThrow(
      'untrusted_callback',
    );
  });

  it('rejects a bare-TLD audience (public-suffix relay bypass)', () => {
    expect(() =>
      parseQRPayload(validQR({ audience: 'com', callbackUrl: 'https://evil.com/cb' })),
    ).toThrow('untrusted_callback');
  });

  it('rejects a non-HTTPS callback (non-localhost)', () => {
    expect(() => parseQRPayload(validQR({ callbackUrl: 'http://app.com/cb' }))).toThrow(
      'untrusted_callback',
    );
  });

  it('allows http on localhost (dev)', () => {
    expect(() =>
      parseQRPayload(validQR({ audience: 'localhost', callbackUrl: 'http://localhost:3000/cb' })),
    ).not.toThrow();
  });

  it('rejects a real-domain audience with a localhost callback (§5.2 relay attempt)', () => {
    expect(() =>
      parseQRPayload(validQR({ audience: 'victim.com', callbackUrl: 'http://localhost:9999/cb' })),
    ).toThrow('untrusted_callback');
  });
});

describe('isSafeReturnUrl', () => {
  it.each([
    ['https://app.com/x', 'app.com', true],
    ['https://sub.app.com/x', 'app.com', true],
    ['http://app.com/x', 'app.com', false],
    ['https://evil.com/x', 'app.com', false],
    ['https://app.com', 'com', false], // bare-TLD audience
    ['javascript:alert(1)', 'app.com', false],
    ['http://localhost/x', 'localhost', true], // dev: local audience + local return
    ['http://localhost/x', 'victim.com', false], // §5.2: real audience + localhost return
    ['', 'app.com', false],
    [null, 'app.com', false],
  ])('isSafeReturnUrl(%s, %s) === %s', (url, audience, expected) => {
    expect(isSafeReturnUrl(url, audience)).toBe(expected);
  });
});
