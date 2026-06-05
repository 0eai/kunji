import { describe, it, expect } from 'vitest';
import {
  mintCapability,
  buildAgentProof,
  verifyCapabilityAssertion,
} from '../src/lib/capability.js';
import {
  generateMasterKey,
  generateEd25519KeyPair,
  exportEd25519PublicKey,
} from '../src/lib/crypto/index.js';

const AUD = 'app.example.com';
const CHALLENGE = 'c'.repeat(64);

const setup = async (mintOver = {}) => {
  const master = await generateMasterKey();
  const agent = generateEd25519KeyPair(); // { secretKey, publicKey }
  const agentPubB64 = exportEd25519PublicKey(agent.publicKey);
  const minted = await mintCapability(master, {
    audience: AUD,
    scope: ['login'],
    ttlSeconds: 300,
    agentPubB64,
    ...mintOver,
  });
  return { master, agent, agentPubB64, minted };
};

const verify = (minted, agent, over = {}) =>
  verifyCapabilityAssertion({
    capability: minted.capability,
    agentProof: buildAgentProof(agent.secretKey, {
      audience: AUD,
      challenge: CHALLENGE,
      capJti: minted.jti,
      ...(over.proof || {}),
    }),
    audience: AUD,
    challenge: CHALLENGE,
    ...over.verify,
  });

describe('capability — happy path', () => {
  it('mint → agent proof → verify resolves to the user sub + scope', async () => {
    const { minted, agent } = await setup();
    const r = await verify(minted, agent);
    expect(r.ok).toBe(true);
    expect(r.sub).toBe(minted.sub);
    expect(r.scope).toEqual(['login']);
    expect(r.sub).toMatch(/^[0-9a-f]{64}$/);
  });

  it('sub is stable for the same (master, audience) across mints', async () => {
    const master = await generateMasterKey();
    const a = generateEd25519KeyPair();
    const apk = exportEd25519PublicKey(a.publicKey);
    const m1 = await mintCapability(master, { audience: AUD, scope: ['login'], ttlSeconds: 60, agentPubB64: apk });
    const m2 = await mintCapability(master, { audience: AUD, scope: ['login'], ttlSeconds: 60, agentPubB64: apk });
    expect(m1.sub).toBe(m2.sub);
    expect(m1.jti).not.toBe(m2.jti); // each capability is unique
  });
});

describe('capability — rejections', () => {
  it('rejects a different audience', async () => {
    const { minted, agent } = await setup();
    const r = await verify(minted, agent, { verify: { audience: 'evil.com' } });
    expect(r).toMatchObject({ ok: false, error: 'audience_mismatch' });
  });

  it('rejects a proof from the WRONG agent key (holder-of-key)', async () => {
    const { minted } = await setup();
    const attacker = generateEd25519KeyPair();
    const r = await verifyCapabilityAssertion({
      capability: minted.capability,
      agentProof: buildAgentProof(attacker.secretKey, { audience: AUD, challenge: CHALLENGE, capJti: minted.jti }),
      audience: AUD,
      challenge: CHALLENGE,
    });
    expect(r).toMatchObject({ ok: false, error: 'bad_agent_proof' });
  });

  it('rejects a proof for the wrong challenge', async () => {
    const { minted, agent } = await setup();
    const r = await verify(minted, agent, { proof: { challenge: 'd'.repeat(64) } });
    expect(r).toMatchObject({ ok: false, error: 'challenge_mismatch' });
  });

  it('rejects an expired capability', async () => {
    const { minted, agent } = await setup({ ttlSeconds: 1 });
    const r = await verify(minted, agent, { verify: { now: Date.now() + 10_000 } });
    expect(r).toMatchObject({ ok: false, error: 'capability_expired' });
  });

  it('rejects a revoked jti', async () => {
    const { minted, agent } = await setup();
    const r = await verify(minted, agent, { verify: { isRevoked: (j) => j === minted.jti } });
    expect(r).toMatchObject({ ok: false, error: 'capability_revoked' });
  });

  it('rejects a tampered capability signature', async () => {
    const { minted, agent } = await setup();
    const parts = minted.capability.split('.');
    // Flip the FIRST signature char (always a significant bit; the last char is only
    // trailing padding bits and may leave the signature valid).
    const tampered = `${parts[0]}.${parts[1]}.${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
    const r = await verifyCapabilityAssertion({
      capability: tampered,
      agentProof: buildAgentProof(agent.secretKey, { audience: AUD, challenge: CHALLENGE, capJti: minted.jti }),
      audience: AUD,
      challenge: CHALLENGE,
    });
    expect(r.ok).toBe(false);
    expect(['bad_cap_signature', 'malformed_capability']).toContain(r.error);
  });

  it('rejects a proof bound to a different capability', async () => {
    const { minted, agent } = await setup();
    const r = await verify(minted, agent, { proof: { capJti: 'not-this-cap' } });
    expect(r).toMatchObject({ ok: false, error: 'proof_cap_mismatch' });
  });
});
