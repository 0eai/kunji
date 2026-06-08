import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  generateMasterKey,
  deriveVaultWriteKeyPair,
  exportEd25519PublicKey,
  signWithEd25519,
} from '../src/lib/crypto/index.js';

// Mirror functions/index.js exactly: canonical JSON (sorted keys, no whitespace) + the verified
// payload reconstruction (kind folded in only when present). Locks the wallet activity signer to
// what vaultWrite will verify for kind:'activity'.
const canonicalJson = (o) =>
  o === null || typeof o !== 'object' || Array.isArray(o)
    ? JSON.stringify(o)
    : JSON.stringify(
        Object.fromEntries(
          Object.keys(o)
            .sort()
            .map((k) => [k, o[k]]),
        ),
      );

const b64 = (s) => Buffer.from(s, 'base64');

const fnPayload = ({ appId, doc, op, publicKey, timestamp, vaultId, kind }) => {
  const p = { appId, doc: doc ?? null, op, publicKey, timestamp, vaultId };
  if (kind !== undefined) p.kind = kind;
  return p;
};

const buildActivityWrite = async (over = {}) => {
  const { secretKey, publicKey } = await deriveVaultWriteKeyPair(await generateMasterKey());
  const pub = exportEd25519PublicKey(publicKey);
  const signed = {
    appId: 'b8f3c0a2-0000-4000-8000-000000000001', // crypto.randomUUID()-shaped, SAFE_ID-ok
    doc: { iv: 'aXY=', data: 'ZGF0YQ==' },
    kind: 'activity',
    op: 'set',
    publicKey: pub,
    timestamp: 1_700_000_000_000,
    vaultId: 'a'.repeat(64),
    ...over,
  };
  return { signed, pub, token: signWithEd25519(signed, secretKey) };
};

describe("vaultWrite kind:'activity' — signer ↔ function parity", () => {
  it('produces a signature the function reconstruction accepts', async () => {
    const { signed, pub, token } = await buildActivityWrite();
    const ok = ed25519.verify(
      b64(token),
      new TextEncoder().encode(canonicalJson(fnPayload(signed))),
      b64(pub),
    );
    expect(ok).toBe(true);
  });

  it('rejects a tampered appId (entry id) — signature is over the original', async () => {
    const { signed, pub, token } = await buildActivityWrite();
    const ok = ed25519.verify(
      b64(token),
      new TextEncoder().encode(canonicalJson(fnPayload({ ...signed, appId: 'tampered-id' }))),
      b64(pub),
    );
    expect(ok).toBe(false);
  });

  it('rejects a flipped kind (cannot re-target a captured activity write)', async () => {
    const { signed, pub, token } = await buildActivityWrite();
    const ok = ed25519.verify(
      b64(token),
      new TextEncoder().encode(canonicalJson(fnPayload({ ...signed, kind: 'profile' }))),
      b64(pub),
    );
    expect(ok).toBe(false);
  });
});

describe("vaultWrite kind:'device' — signer ↔ function parity", () => {
  it('produces a signature the function reconstruction accepts', async () => {
    const { signed, pub, token } = await buildActivityWrite({ kind: 'device' });
    const ok = ed25519.verify(
      b64(token),
      new TextEncoder().encode(canonicalJson(fnPayload(signed))),
      b64(pub),
    );
    expect(ok).toBe(true);
  });
});
