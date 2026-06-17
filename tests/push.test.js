import { describe, it, expect } from 'vitest';
import { generateMasterKey, deriveChannelId, generateEd25519KeyPair } from '../src/lib/crypto/index.js';
import { buildAgentProof, okpJwk } from '../src/lib/capability.js';
import { verifyPostProof, verifyPostProofAny } from '../functions/pushProof.js';

// Push relay (push-relay.md Transport ②). The channelId is an opaque, per-audience mailbox derived
// from the master key; only the holder of the channel's registered key (postKeyJwk) can ping it,
// proven with a buildAgentProof bound to (channelId, requestId). pushDispatch's verifyPostProof gates it.

describe('deriveChannelId', () => {
  it('is 64-hex, deterministic per (master, audience), per-audience, and domain-normalized', async () => {
    const master = await generateMasterKey();
    const a = await deriveChannelId(master, 'app.example');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await deriveChannelId(master, 'app.example')).toBe(a); // deterministic
    expect(await deriveChannelId(master, 'other.example')).not.toBe(a); // per-audience
    expect(await deriveChannelId(master, 'App.Example')).toBe(a); // normalizeDomain (case)
    const other = await generateMasterKey();
    expect(await deriveChannelId(other, 'app.example')).not.toBe(a); // per-master
  });
});

describe('verifyPostProof (holder-of-key gate for pushDispatch)', () => {
  const CHANNEL = 'c'.repeat(64);
  const REQ = '123456';
  const mk = () => {
    const agent = generateEd25519KeyPair();
    const postKeyJwk = okpJwk(agent.publicKey);
    const proof = buildAgentProof(agent.secretKey, { audience: CHANNEL, challenge: REQ, capJti: CHANNEL });
    return { agent, postKeyJwk, proof };
  };

  it('accepts a fresh, channel+request-bound proof signed by the registered key', () => {
    const { postKeyJwk, proof } = mk();
    expect(verifyPostProof(proof, postKeyJwk, CHANNEL, REQ)).toBe(true);
  });

  it('rejects a proof signed by a different key', () => {
    const { proof } = mk();
    const attacker = generateEd25519KeyPair();
    expect(verifyPostProof(proof, okpJwk(attacker.publicKey), CHANNEL, REQ)).toBe(false);
  });

  it('rejects a proof bound to a different channel or request (no cross-use / replay-elsewhere)', () => {
    const { postKeyJwk, proof } = mk();
    expect(verifyPostProof(proof, postKeyJwk, 'd'.repeat(64), REQ)).toBe(false);
    expect(verifyPostProof(proof, postKeyJwk, CHANNEL, '999999')).toBe(false);
  });

  it('rejects a stale proof and a malformed token', () => {
    const { agent, postKeyJwk } = mk();
    const old = buildAgentProof(agent.secretKey, {
      audience: CHANNEL,
      challenge: REQ,
      capJti: CHANNEL,
      now: Date.now() - 5 * 60 * 1000,
    });
    expect(verifyPostProof(old, postKeyJwk, CHANNEL, REQ)).toBe(false);
    expect(verifyPostProof('not.a.jwt', postKeyJwk, CHANNEL, REQ)).toBe(false);
    expect(verifyPostProof(null, postKeyJwk, CHANNEL, REQ)).toBe(false);
  });
});

describe('verifyPostProofAny (multi-poster dispatch gate, 4.3)', () => {
  const CHANNEL = 'c'.repeat(64);
  const REQ = '123456';
  const poster = () => {
    const agent = generateEd25519KeyPair();
    return {
      jwk: okpJwk(agent.publicKey),
      proof: buildAgentProof(agent.secretKey, { audience: CHANNEL, challenge: REQ, capJti: CHANNEL }),
    };
  };

  it('accepts a proof from ANY authorized poster in the postKeyJwks map', () => {
    const a = poster();
    const b = poster();
    const map = { [a.jwk.x]: a.jwk, [b.jwk.x]: b.jwk };
    expect(verifyPostProofAny(a.proof, map, CHANNEL, REQ)).toBe(true);
    expect(verifyPostProofAny(b.proof, map, CHANNEL, REQ)).toBe(true);
  });

  it('rejects a proof from an UNauthorized key not in the map', () => {
    const a = poster();
    const stranger = poster();
    expect(verifyPostProofAny(stranger.proof, { [a.jwk.x]: a.jwk }, CHANNEL, REQ)).toBe(false);
  });

  it('a removed poster (dropped from the map) can no longer ping', () => {
    const a = poster();
    const b = poster();
    const after = { [b.jwk.x]: b.jwk }; // a was removed
    expect(verifyPostProofAny(a.proof, after, CHANNEL, REQ)).toBe(false);
    expect(verifyPostProofAny(b.proof, after, CHANNEL, REQ)).toBe(true);
  });

  it('accepts an array of keys and an empty/missing set rejects', () => {
    const a = poster();
    expect(verifyPostProofAny(a.proof, [a.jwk], CHANNEL, REQ)).toBe(true);
    expect(verifyPostProofAny(a.proof, {}, CHANNEL, REQ)).toBe(false);
    expect(verifyPostProofAny(a.proof, undefined, CHANNEL, REQ)).toBe(false);
  });
});
