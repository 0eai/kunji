import { describe, it, expect, vi } from 'vitest';

// vault.js pulls in Firebase at import; stub it so these pure helpers run in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('firebase/firestore', () => ({
  doc: vi.fn(),
  getDoc: vi.fn(),
  setDoc: vi.fn(),
  deleteField: vi.fn(),
}));

import {
  RECOVERY_FILE_FORMAT,
  buildRecoveryEnvelope,
  recoveryFileName,
  extractRecoveryKey,
} from '../src/services/vault.js';

const V2 = 'v2:' + btoa(JSON.stringify({ salt: 'abc', argon2: { m: 1, t: 1, p: 1 }, iv: 'x', data: 'y' }));

describe('recovery file packaging', () => {
  it('round-trips: buildRecoveryEnvelope → extractRecoveryKey returns the original v2 string', () => {
    const envelope = buildRecoveryEnvelope(V2);
    const parsed = JSON.parse(envelope);
    expect(parsed.format).toBe(RECOVERY_FILE_FORMAT);
    expect(parsed.v).toBe(2);
    expect(extractRecoveryKey(envelope)).toBe(V2);
  });

  it('the envelope carries NO identifiers — only format/v/key', () => {
    expect(Object.keys(JSON.parse(buildRecoveryEnvelope(V2))).sort()).toEqual(['format', 'key', 'v']);
  });

  it('extractRecoveryKey accepts a raw v2: text file (hand-saved / back-compat)', () => {
    expect(extractRecoveryKey(V2)).toBe(V2);
    expect(extractRecoveryKey(`  ${V2}\n`)).toBe(V2); // tolerant of whitespace
  });

  it('rejects junk, wrong format, and envelopes whose key is not a v2 string', () => {
    expect(() => extractRecoveryKey('not a recovery file')).toThrow('INVALID_RECOVERY_FILE');
    expect(() => extractRecoveryKey('')).toThrow('INVALID_RECOVERY_FILE');
    expect(() => extractRecoveryKey(JSON.stringify({ format: 'something-else', key: V2 }))).toThrow(
      'INVALID_RECOVERY_FILE',
    );
    expect(() =>
      extractRecoveryKey(JSON.stringify({ format: RECOVERY_FILE_FORMAT, v: 2, key: 'bogus' })),
    ).toThrow('INVALID_RECOVERY_FILE');
  });

  it('recoveryFileName is date-stamped with the .kunji extension', () => {
    expect(recoveryFileName(new Date('2026-06-07T10:00:00Z'))).toBe('kunji-recovery-2026-06-07.kunji');
  });
});
