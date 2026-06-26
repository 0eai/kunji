import { describe, it, expect, vi } from 'vitest';

// capability.js pulls in Firebase at import; stub it so the pure parser runs in Node.
vi.mock('../src/lib/firebase', () => ({ db: {} }));
vi.mock('firebase/firestore', () => ({ doc: vi.fn(), setDoc: vi.fn() }));

import { parseAgentRequest } from '../src/services/capability.js';
import {
  generateECDHKeyPair,
  exportECDHPublicKey,
  exportECDHPrivateKey,
  importECDHPublicKey,
  deriveECDHSharedSecret,
  encryptData,
} from '../src/lib/crypto/index.js';
// The bridge's actual decrypt path (Node WebCrypto), exercised against the wallet's encrypt.
import { decryptRelayedCapability } from '../examples/kunji-mcp/capability-client.js';

const HEX64 = 'a'.repeat(64);
const AGENT_PUB = 'A'.repeat(43) + '='; // shape-valid base64 Ed25519 pub

describe('agent capability relay — wallet ↔ bridge ECDH/AES parity', () => {
  it('a capability the wallet ECDH-encrypts is decrypted by the bridge', async () => {
    const jwt = 'eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJleGFtcGxlLmNvbSJ9.SIGSIGSIG';

    // Agent side: ephemeral ECDH keypair; the bridge holds the pkcs8 priv, the request carries the spki pub.
    const agent = await generateECDHKeyPair();
    const agentTransportPub = await exportECDHPublicKey(agent.publicKey);
    const transportPrivB64 = await exportECDHPrivateKey(agent.privateKey);

    // Wallet side (mirrors depositAgentCapability): fresh keypair, derive shared to the agent's pub, encrypt.
    const wallet = await generateECDHKeyPair();
    const walletPubE = await exportECDHPublicKey(wallet.publicKey);
    const shared = await deriveECDHSharedSecret(wallet.privateKey, await importECDHPublicKey(agentTransportPub));
    const encryptedCapability = await encryptData(jwt, shared);

    // Bridge side: decrypt with the transport priv + wallet's ephemeral pub.
    const recovered = await decryptRelayedCapability({ transportPrivB64, walletPubE, encryptedCapability });
    expect(recovered).toBe(jwt);
  });

  it('the push channelId rides the SAME encrypted relay (auto-handoff, no copy/paste)', async () => {
    const channelId = 'c'.repeat(64);
    const agent = await generateECDHKeyPair();
    const agentTransportPub = await exportECDHPublicKey(agent.publicKey);
    const transportPrivB64 = await exportECDHPrivateKey(agent.privateKey);
    const wallet = await generateECDHKeyPair();
    const walletPubE = await exportECDHPublicKey(wallet.publicKey);
    const shared = await deriveECDHSharedSecret(wallet.privateKey, await importECDHPublicKey(agentTransportPub));
    // depositAgentCapability adds `encryptedChannel` with the SAME shared secret when push is on.
    const encryptedChannel = await encryptData(channelId, shared);
    const recovered = await decryptRelayedCapability({ transportPrivB64, walletPubE, encryptedCapability: encryptedChannel });
    expect(recovered).toBe(channelId);
  });
});

describe('parseAgentRequest — v1 unchanged, v2 validated', () => {
  const v1 = { kunjiCap: 'v1', audience: 'example.com', scope: ['login'], agentPub: AGENT_PUB };

  it('accepts a v1 request (paste-only) without relay fields', () => {
    const out = parseAgentRequest(JSON.stringify(v1));
    expect(out).toMatchObject({ audience: 'example.com', scope: ['login'], agentPub: AGENT_PUB });
    expect(out.sessionId).toBeUndefined();
    expect(out.transportPub).toBeUndefined();
  });

  it('accepts a well-formed v2 request and returns the relay fields', async () => {
    const kp = await generateECDHKeyPair();
    const transportPub = await exportECDHPublicKey(kp.publicKey);
    const out = parseAgentRequest(JSON.stringify({ ...v1, kunjiCap: 'v2', transportPub, sessionId: HEX64 }));
    expect(out.transportPub).toBe(transportPub);
    expect(out.sessionId).toBe(HEX64);
  });

  it('rejects a v2 request with a malformed sessionId or transportPub (no silent downgrade)', () => {
    const kp = { transportPub: 'not-base64!!', sessionId: HEX64 };
    expect(() => parseAgentRequest(JSON.stringify({ ...v1, kunjiCap: 'v2', ...kp }))).toThrow('invalid_request');
    expect(() =>
      parseAgentRequest(JSON.stringify({ ...v1, kunjiCap: 'v2', transportPub: 'A'.repeat(124), sessionId: 'short' })),
    ).toThrow('invalid_request');
  });

  it('rejects an unknown version', () => {
    expect(() => parseAgentRequest(JSON.stringify({ ...v1, kunjiCap: 'v9' }))).toThrow('invalid_request');
  });
});
