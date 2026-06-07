// kunji MCP bridge — capability client (agent side).
//
// Holds the AGENT's keypair locally (never leaves this machine), ingests a capability
// minted by the user's kunji wallet, and performs holder-of-key logins against a relying
// party. The kunji master/per-app keys are never seen here — only a scoped, expiring
// capability + the agent's own key. See ../../docs/agentic-delegation.md.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

const STATE = join(dirname(fileURLToPath(import.meta.url)), '.mcp-state.json');

const b64u = {
  fromBytes: (b) => Buffer.from(b).toString('base64url'),
  toBytes: (s) => new Uint8Array(Buffer.from(String(s), 'base64url')),
  toJSON: (s) => JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')),
  fromString: (s) => Buffer.from(String(s), 'utf8').toString('base64url'),
};
const enc = (s) => new TextEncoder().encode(s);
const loadState = () => (existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {});
const saveState = (s) => writeFileSync(STATE, JSON.stringify(s, null, 2));

// kunji app origin that hosts the capability relay (agentCapabilityPoll). Override for local dev.
const KUNJI_APP_URL = (process.env.KUNJI_APP_URL || 'https://app.kunji.cc').replace(/\/$/, '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── ECDH P-256 + AES-GCM, mirroring src/lib/crypto/{ecdh,aes}.js byte-for-byte (SPKI pubkeys,
// ECDH→AES-GCM-256 via WebCrypto deriveKey, {iv,data} std-base64), using Node's built-in
// WebCrypto — so a capability the wallet ECDH-encrypts decrypts here. The transport key is
// ephemeral per kunji_authorize; the persistent holder-of-key agent key (Ed25519) is separate.
const subtle = globalThis.crypto.subtle;
const genECDH = () =>
  subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
const exportSpkiB64 = async (pub) => Buffer.from(await subtle.exportKey('spki', pub)).toString('base64');
const exportPkcs8B64 = async (priv) => Buffer.from(await subtle.exportKey('pkcs8', priv)).toString('base64');
const importSpki = (b64) =>
  subtle.importKey('spki', Buffer.from(b64, 'base64'), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
const importPkcs8 = (b64) =>
  subtle.importKey('pkcs8', Buffer.from(b64, 'base64'), { name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveKey',
    'deriveBits',
  ]);
const deriveShared = (priv, pub) =>
  subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, [
    'decrypt',
  ]);
const aesGcmDecrypt = async ({ iv, data }, key) => {
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(iv, 'base64') },
    key,
    Buffer.from(data, 'base64'),
  );
  return JSON.parse(Buffer.from(pt).toString('utf8')); // encryptData JSON-stringifies; undo it
};

/**
 * Decrypt a capability the wallet ECDH-encrypted to our transport key. Pure (no I/O) so the
 * wallet↔bridge crypto parity is unit-testable. Returns the capability JWT string.
 */
export const decryptRelayedCapability = async ({ transportPrivB64, walletPubE, encryptedCapability }) => {
  const priv = await importPkcs8(transportPrivB64);
  const shared = await deriveShared(priv, await importSpki(walletPubE));
  return aesGcmDecrypt(encryptedCapability, shared);
};

/**
 * The agent's persistent Ed25519 keypair. The wallet binds capabilities to this key
 * (holder-of-key); the private key never leaves this machine and is never transmitted.
 */
export const agentKey = () => {
  const st = loadState();
  let sk = st.agentSecretKeyB64 ? b64u.toBytes(st.agentSecretKeyB64) : null;
  if (!sk) {
    sk = ed25519.keygen().secretKey;
    saveState({ ...st, agentSecretKeyB64: b64u.fromBytes(sk) });
  }
  return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) };
};

const agentPubB64 = () => Buffer.from(agentKey().publicKey).toString('base64');

const signJWS = (header, claims, sk) => {
  const input = `${b64u.fromString(JSON.stringify(header))}.${b64u.fromString(JSON.stringify(claims))}`;
  return `${input}.${b64u.fromBytes(ed25519.sign(enc(input), sk))}`;
};
const buildAgentProof = (sk, { audience, challenge, capJti }) =>
  signJWS(
    { alg: 'EdDSA', typ: 'kunji-agentproof+jwt' },
    { aud: audience, challenge, iat: Math.floor(Date.now() / 1000), jti: randomBytes(16).toString('hex'), cap: capJti },
    sk,
  );

/**
 * The request the user authorizes in their kunji wallet (Security → Authorize an agent).
 * v2 carries an ephemeral ECDH transport key + a session id so the wallet can deliver the
 * minted capability back over the encrypted relay — no manual copy. The transport private
 * key is held locally (per session) until awaitCapability consumes it.
 */
export const agentRequest = async (audience, scope) => {
  const { publicKey, privateKey } = await genECDH();
  const transportPub = await exportSpkiB64(publicKey);
  const sessionId = randomBytes(32).toString('hex');
  const st = loadState();
  saveState({
    ...st,
    lastSessionId: sessionId,
    relays: { ...(st.relays || {}), [sessionId]: { transportPriv: await exportPkcs8B64(privateKey) } },
  });
  return {
    kunjiCap: 'v2',
    audience,
    scope: scope && scope.length ? scope : ['login'],
    agentPub: agentPubB64(),
    transportPub,
    sessionId,
  };
};

/**
 * Poll the relay for the capability the wallet deposited after the user approved, decrypt it
 * with our transport key, and validate+store it (same checks as kunji_set_capability). No copy.
 */
export const awaitCapability = async (sessionId, { tries = 15, intervalMs = 2000 } = {}) => {
  const st = loadState();
  const sid = sessionId || st.lastSessionId;
  const relay = sid && st.relays?.[sid];
  if (!relay) throw new Error('No pending authorization. Call kunji_authorize first.');

  for (let i = 0; i < tries; i++) {
    const resp = await fetch(`${KUNJI_APP_URL}/agent/capability?sessionId=${sid}`);
    if (resp.status === 410) throw new Error('Authorization expired before it was approved — re-run kunji_authorize.');
    if (resp.ok) {
      const { walletPubE, encryptedCapability } = await resp.json();
      const capability = await decryptRelayedCapability({
        transportPrivB64: relay.transportPriv,
        walletPubE,
        encryptedCapability,
      }); // → the JWT string
      const cap = setCapability(capability); // holder-of-key + expiry validation, then persist
      const next = loadState();
      delete next.relays?.[sid];
      saveState(next);
      return cap;
    }
    // 404 = not approved yet; 429 = backing off — wait and retry.
    await sleep(intervalMs);
  }
  throw new Error('Timed out waiting for approval. Approve it in the wallet, then call kunji_await_capability again.');
};

/** Ingest + validate a capability the user pasted from the wallet, binding it to our key. */
export const setCapability = (capability) => {
  const parts = String(capability).trim().split('.');
  if (parts.length !== 3) throw new Error('That is not a kunji capability token.');
  let claims;
  try {
    claims = b64u.toJSON(parts[1]);
  } catch {
    throw new Error('Malformed capability token.');
  }
  const cnfX = claims?.cnf?.jwk?.x;
  const mine = agentKey().publicKey;
  if (!cnfX || Buffer.compare(Buffer.from(b64u.toBytes(cnfX)), Buffer.from(mine)) !== 0) {
    throw new Error(
      'This capability was issued for a different agent key. Run kunji_authorize again and authorize THAT request in the wallet.',
    );
  }
  if (typeof claims.exp !== 'number' || Date.now() > claims.exp * 1000) {
    throw new Error('This capability has already expired — re-authorize a fresh one.');
  }
  const cap = { audience: claims.aud, scope: claims.scope, exp: claims.exp, jti: claims.jti };
  saveState({ ...loadState(), capability: parts.join('.'), cap });
  return cap;
};

export const currentCapability = () => {
  const st = loadState();
  return { agentPub: agentPubB64(), cap: st.cap || null, hasCapability: !!st.capability };
};

/**
 * Perform a holder-of-key login at `baseUrl` using the stored capability: create a
 * session, sign the challenge with the agent key, POST /kunji/agent, return the result.
 */
export const login = async (baseUrl) => {
  const st = loadState();
  if (!st.capability || !st.cap) {
    throw new Error('No capability set. Call kunji_authorize, approve it in the wallet, then kunji_set_capability.');
  }
  const { audience, scope, exp, jti } = st.cap;
  if (Date.now() > exp * 1000) throw new Error('Capability expired — re-authorize.');

  const base = String(baseUrl).replace(/\/$/, '');
  const post = (p, body) =>
    fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(
      (r) => r.json(),
    );

  const session = await post('/api/session', { audience, callbackUrl: `${base}/kunji/callback` });
  if (!session.sessionId || !session.challenge) {
    throw new Error('createSession failed: ' + JSON.stringify(session));
  }
  const agentProof = buildAgentProof(agentKey().secretKey, { audience, challenge: session.challenge, capJti: jti });
  const res = await post('/kunji/agent', { sessionId: session.sessionId, capability: st.capability, agentProof });
  if (res.error) throw new Error('Agent login rejected: ' + res.error);

  const status = await fetch(`${base}/kunji/status?sessionId=${session.sessionId}`).then((r) => r.json());
  return { audience, scope, sub: status.sub || null, status: status.status };
};
