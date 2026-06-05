import { describe, it, expect } from 'vitest';
// Wallet (browser) mint/proof ↔ RP (Node) verifier — guards against the two
// implementations drifting, the way verify.test.js does for the §6 assertion.
import { mintCapability, buildAgentProof } from '../src/lib/capability.js';
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
});
