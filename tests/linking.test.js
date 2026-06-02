import { describe, it, expect, vi } from 'vitest';

// linking.js imports Firebase at module load; stub it so the pure crypto runs in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('../src/services/activityLog', () => ({ logActivity: vi.fn() }));

import { deriveLinkSas } from '../src/services/linking.js';
import {
  generateECDHKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
} from '../src/lib/crypto/index.js';

const pub = async (kp) => importECDHPublicKey(await exportECDHPublicKey(kp.publicKey));

describe('deriveLinkSas (device-link SAS)', () => {
  it('both sides of an ECDH exchange derive the SAME 6-digit SAS, deterministically', async () => {
    const a = await generateECDHKeyPair(); // issuer
    const b = await generateECDHKeyPair(); // new device
    const sasA = await deriveLinkSas(a.privateKey, await pub(b));
    const sasB = await deriveLinkSas(b.privateKey, await pub(a));

    expect(sasA).toMatch(/^\d{3}-\d{3}$/);
    expect(sasA).toBe(sasB); // the user-comparable codes match → no substitution
    expect(await deriveLinkSas(a.privateKey, await pub(b))).toBe(sasA); // deterministic
  });

  it('a substituted (MITM) peer key yields a DIFFERENT SAS → mismatch is detectable', async () => {
    const a = await generateECDHKeyPair(); // issuer
    const b = await generateECDHKeyPair(); // intended new device
    const m = await generateECDHKeyPair(); // attacker who planted its own key

    const sasLegit = await deriveLinkSas(a.privateKey, await pub(b));
    const sasWithAttacker = await deriveLinkSas(a.privateKey, await pub(m));
    const sasOnRealDevice = await deriveLinkSas(b.privateKey, await pub(a));

    // The issuer paired with the attacker shows a SAS the real new device cannot match.
    expect(sasWithAttacker).not.toBe(sasOnRealDevice);
    expect(sasWithAttacker).not.toBe(sasLegit);
  });
});
