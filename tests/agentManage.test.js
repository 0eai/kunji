import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { mintCapability, buildAgentProof } from '../src/lib/capability.js';
import {
  verifyCapabilityAssertion,
  revokeMessage,
} from '../examples/kunji-login-demo/functions/capability.js';
import {
  generateMasterKey,
  generateEd25519KeyPair,
  exportEd25519PublicKey,
  deriveVaultWriteKeyPair,
  deriveAppKeyPair,
  signWithEd25519,
  signMessageEd25519,
} from '../src/lib/crypto/index.js';

const AUD = 'app.example.com';
const CHALLENGE = 'c'.repeat(64);

// ── vaultWrite kind:'agent' signer ↔ function parity (mirror functions/index.js) ──
const canonicalJson = (o) =>
  o === null || typeof o !== 'object' || Array.isArray(o)
    ? JSON.stringify(o)
    : JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));
const b64 = (s) => Buffer.from(s, 'base64');
const fnPayload = ({ appId, doc, op, publicKey, timestamp, vaultId, kind }) => {
  const p = { appId, doc: doc ?? null, op, publicKey, timestamp, vaultId };
  if (kind !== undefined) p.kind = kind;
  return p;
};

describe("vaultWrite kind:'agent' — signer ↔ function parity", () => {
  it('signs an agent record write the function reconstruction accepts', async () => {
    const { secretKey, publicKey } = await deriveVaultWriteKeyPair(await generateMasterKey());
    const pub = exportEd25519PublicKey(publicKey);
    const signed = {
      appId: 'deadbeef'.repeat(4), // jti (hex) → SAFE_ID
      doc: { iv: 'aXY=', data: 'ZGF0YQ==' },
      kind: 'agent',
      op: 'set',
      publicKey: pub,
      timestamp: 1_700_000_000_000,
      vaultId: 'a'.repeat(64),
    };
    const token = signWithEd25519(signed, secretKey);
    const ok = ed25519.verify(b64(token), new TextEncoder().encode(canonicalJson(fnPayload(signed))), b64(pub));
    expect(ok).toBe(true);
  });
});

// ── Issuer-signed revocation parity (wallet sign → RP verify) ──
const mintFor = async (master, scope = ['login'], ttlSeconds = 300) => {
  const agent = generateEd25519KeyPair();
  const minted = await mintCapability(master, {
    audience: AUD,
    scope,
    ttlSeconds,
    agentPubB64: exportEd25519PublicKey(agent.publicKey),
  });
  const agentProof = buildAgentProof(agent.secretKey, { audience: AUD, challenge: CHALLENGE, capJti: minted.jti });
  return { minted, agentProof };
};

describe('issuer-signed revocation parity', () => {
  it('a revocation signed by the capability’s own per-app key is honored', async () => {
    const master = await generateMasterKey();
    const { minted, agentProof } = await mintFor(master);
    const { secretKey: appSk } = await deriveAppKeyPair(master, AUD);
    const sig = signMessageEd25519(revokeMessage(minted.jti), appSk);

    const r = await verifyCapabilityAssertion({
      capability: minted.capability,
      agentProof,
      audience: AUD,
      challenge: CHALLENGE,
      getRevocation: async (jti) => (jti === minted.jti ? { sig } : null),
    });
    expect(r).toMatchObject({ ok: false, error: 'capability_revoked' });
  });

  it('a revocation signed by a DIFFERENT key is ignored (login still succeeds)', async () => {
    const master = await generateMasterKey();
    const { minted, agentProof } = await mintFor(master);
    const attacker = generateEd25519KeyPair();
    const forged = signMessageEd25519(revokeMessage(minted.jti), attacker.secretKey);

    const r = await verifyCapabilityAssertion({
      capability: minted.capability,
      agentProof,
      audience: AUD,
      challenge: CHALLENGE,
      getRevocation: async () => ({ sig: forged }),
    });
    expect(r).toMatchObject({ ok: true, jti: minted.jti });
  });
});
