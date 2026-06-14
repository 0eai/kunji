import { describe, it, expect } from 'vitest';
import {
  generateMasterKey,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../src/lib/crypto/index.js';
import { verifySignedWrite, canonicalJson } from '../functions/signedWrite.js';

// S22 hardening: push-channel registration is a SIGNED write (master-key-derived vault-write key),
// verified by the pushChannelRegister function + TOFU-bound per channelId. These tests cover the
// signature CONTRACT — the wallet signer (signWithEd25519) ↔ the function verify (verifySignedWrite) —
// which is what makes a leaked channelId unwritable without the master key. (The TOFU "registered key
// must match" transaction is function-level, exercised on deploy smoke, like vaultWrite's.)

const CHANNEL = 'a'.repeat(64);
const SUB = { endpoint: 'https://push.example/x', keys: { p256dh: 'p', auth: 'a' } };
const JWK = { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' };

const vaultWriteKey = async (master) => {
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(master);
  return { secretKey, publicKey: exportEd25519PublicKey(publicKey) };
};

describe('push channel signed-write contract (S22)', () => {
  it('a register payload signed by the vault-write key verifies (client signer ↔ function verify)', async () => {
    const { secretKey, publicKey } = await vaultWriteKey(await generateMasterKey());
    const payload = { channelId: CHANNEL, op: 'set', postKeyJwk: JWK, pushSub: SUB, publicKey, timestamp: Date.now() };
    const signedToken = signWithEd25519(payload, secretKey);
    expect(verifySignedWrite(payload, signedToken, publicKey)).toBe(true);
  });

  it('a delete payload round-trips too', async () => {
    const { secretKey, publicKey } = await vaultWriteKey(await generateMasterKey());
    const payload = { channelId: CHANNEL, op: 'delete', publicKey, timestamp: Date.now() };
    expect(verifySignedWrite(payload, signWithEd25519(payload, secretKey), publicKey)).toBe(true);
  });

  it('rejects a tampered field (canonical JSON binds every field of the request)', async () => {
    const { secretKey, publicKey } = await vaultWriteKey(await generateMasterKey());
    const payload = { channelId: CHANNEL, op: 'delete', publicKey, timestamp: Date.now() };
    const signedToken = signWithEd25519(payload, secretKey);
    expect(verifySignedWrite({ ...payload, op: 'set' }, signedToken, publicKey)).toBe(false); // op flipped
    expect(verifySignedWrite({ ...payload, channelId: 'b'.repeat(64) }, signedToken, publicKey)).toBe(false);
  });

  it('a signature from a DIFFERENT key cannot claim the vault-write pubkey (no forging as the holder)', async () => {
    const { publicKey } = await vaultWriteKey(await generateMasterKey()); // the victim's vault-write pubkey
    const attacker = await vaultWriteKey(await generateMasterKey());
    const payload = { channelId: CHANNEL, op: 'delete', publicKey, timestamp: Date.now() };
    const forged = signWithEd25519(payload, attacker.secretKey); // attacker signs, but claims the victim pubkey
    expect(verifySignedWrite(payload, forged, publicKey)).toBe(false);
    // (If the attacker instead claims their OWN pubkey, the function's per-channelId TOFU rejects it.)
  });

  it('canonicalJson sorts top-level keys (matches the client signer)', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson({ z: { y: 1 }, a: 'x' })).toBe('{"a":"x","z":{"y":1}}');
  });
});
