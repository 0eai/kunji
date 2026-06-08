import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// capability.js pulls in Firebase at import; stub it so the pure helpers run in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('firebase/firestore', () => ({ collection: vi.fn(), doc: vi.fn(), getDocs: vi.fn(), setDoc: vi.fn() }));

import { parseAgentRequest, lookupAgentRequest } from '../src/services/capability.js';
import { generateECDHKeyPair, exportECDHPublicKey } from '../src/lib/crypto/index.js';

const HEX64 = 'a'.repeat(64);
const AGENT_PUB = 'A'.repeat(43) + '='; // shape-valid base64 Ed25519 pub

// The exact fields agentRequestRelay persists into agentRequests/{code} (it stores only these).
const storedShape = async () => {
  const kp = await generateECDHKeyPair();
  return {
    kunjiCap: 'v2',
    audience: 'example.com',
    scope: ['login'],
    agentPub: AGENT_PUB,
    transportPub: await exportECDHPublicKey(kp.publicKey),
    sessionId: HEX64,
  };
};

describe('OTP relay — stored request round-trips through parseAgentRequest', () => {
  it('the relay-stored shape is exactly what the wallet validator accepts', async () => {
    const req = await storedShape();
    const out = parseAgentRequest(JSON.stringify(req));
    expect(out).toMatchObject({ audience: 'example.com', scope: ['login'], agentPub: AGENT_PUB });
    expect(out.transportPub).toBe(req.transportPub);
    expect(out.sessionId).toBe(HEX64);
  });
});

describe('lookupAgentRequest — code → request fetch', () => {
  const realFetch = globalThis.fetch;
  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('rejects a non-6-digit code before any fetch', async () => {
    await expect(lookupAgentRequest('12ab')).rejects.toThrow('6-digit');
    await expect(lookupAgentRequest('1234')).rejects.toThrow('6-digit');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('returns the raw JSON (ready for parseAgentRequest) on success', async () => {
    const req = await storedShape();
    const body = JSON.stringify(req);
    globalThis.fetch.mockResolvedValue({ ok: true, status: 200, text: () => Promise.resolve(body) });
    const raw = await lookupAgentRequest('123456');
    expect(raw).toBe(body);
    expect(() => parseAgentRequest(raw)).not.toThrow();
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining('code=123456'));
  });

  it('maps 404 / 410 / 429 to friendly errors', async () => {
    globalThis.fetch.mockResolvedValue({ ok: false, status: 404, text: () => Promise.resolve('') });
    await expect(lookupAgentRequest('123456')).rejects.toThrow('not found');
    globalThis.fetch.mockResolvedValue({ ok: false, status: 410, text: () => Promise.resolve('') });
    await expect(lookupAgentRequest('123456')).rejects.toThrow('expired');
    globalThis.fetch.mockResolvedValue({ ok: false, status: 429, text: () => Promise.resolve('') });
    await expect(lookupAgentRequest('123456')).rejects.toThrow('Too many');
  });
});
