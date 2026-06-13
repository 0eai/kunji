import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// Wallet (browser) mint/proof ↔ RP (Node) verifier — guards against the two
// implementations drifting, the way verify.test.js does for the §6 assertion.
import { mintCapability, mintDelegatedCapability, buildAgentProof } from '../src/lib/capability.js';
import { verifyCapabilityAssertion } from '../examples/kunji-login-demo/functions/capability.js';
import {
  generateMasterKey,
  generateEd25519KeyPair,
  exportEd25519PublicKey,
} from '../src/lib/crypto/index.js';

const AUD = 'app.example.com';
const CHALLENGE = 'c'.repeat(64);

const mint = async (scope = ['login', 'read:profile'], ttlSeconds = 300) => {
  const master = await generateMasterKey();
  const agent = generateEd25519KeyPair();
  const agentPubB64 = exportEd25519PublicKey(agent.publicKey);
  const minted = await mintCapability(master, { audience: AUD, scope, ttlSeconds, agentPubB64 });
  return { agent, minted };
};

describe('capability parity (wallet mint → RP verify)', () => {
  it('a wallet-minted capability + agent proof verifies in the Node RP verifier', async () => {
    const { agent, minted } = await mint();
    const agentProof = buildAgentProof(agent.secretKey, {
      audience: AUD,
      challenge: CHALLENGE,
      capJti: minted.jti,
    });
    const r = await verifyCapabilityAssertion({
      capability: minted.capability,
      agentProof,
      audience: AUD,
      challenge: CHALLENGE,
    });
    expect(r).toMatchObject({ ok: true, sub: minted.sub, scope: ['login', 'read:profile'] });
  });

  it('the RP verifier enforces revocation and holder-of-key', async () => {
    const { agent, minted } = await mint(['login']);
    const goodProof = buildAgentProof(agent.secretKey, {
      audience: AUD,
      challenge: CHALLENGE,
      capJti: minted.jti,
    });
    const revoked = await verifyCapabilityAssertion({
      capability: minted.capability,
      agentProof: goodProof,
      audience: AUD,
      challenge: CHALLENGE,
      isRevoked: (j) => j === minted.jti,
    });
    expect(revoked).toMatchObject({ ok: false, error: 'capability_revoked' });

    const attacker = generateEd25519KeyPair();
    const badProof = buildAgentProof(attacker.secretKey, {
      audience: AUD,
      challenge: CHALLENGE,
      capJti: minted.jti,
    });
    const r = await verifyCapabilityAssertion({
      capability: minted.capability,
      agentProof: badProof,
      audience: AUD,
      challenge: CHALLENGE,
    });
    expect(r).toMatchObject({ ok: false, error: 'bad_agent_proof' });
  });

  it('the RP verifier enforces a wallet-minted delegation chain (narrow-not-widen)', async () => {
    const master = await generateMasterKey();
    const agentA = generateEd25519KeyPair();
    const root = await mintCapability(master, {
      audience: AUD,
      scope: ['read:orders', 'read:invoices'],
      ttlSeconds: 300,
      agentPubB64: exportEd25519PublicKey(agentA.publicKey),
    });
    const agentB = generateEd25519KeyPair();
    const child = mintDelegatedCapability(root.capability, agentA.secretKey, {
      scope: ['read:orders'],
      agentPubB64: exportEd25519PublicKey(agentB.publicKey),
      ttlSeconds: 120,
    });
    const r = await verifyCapabilityAssertion({
      capability: root.capability,
      chain: [child.capability],
      agentProof: buildAgentProof(agentB.secretKey, { audience: AUD, challenge: CHALLENGE, capJti: child.jti }),
      audience: AUD,
      challenge: CHALLENGE,
    });
    expect(r).toMatchObject({ ok: true, sub: root.sub, scope: ['read:orders'], jti: child.jti });
  });

  // kunji-agent-demo ships its own copy of the RP verifier (it's a plain-Node RP with no shared
  // import path). The parity above only exercises the kunji-login-demo copy — so guard that the
  // agent-demo copy stays byte-identical to it, and the parity guarantee carries over.
  it('kunji-agent-demo/capability.js is byte-identical to the guarded login-demo copy', () => {
    const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
    expect(read('../examples/kunji-agent-demo/capability.js')).toBe(
      read('../examples/kunji-login-demo/functions/capability.js'),
    );
  });
});
