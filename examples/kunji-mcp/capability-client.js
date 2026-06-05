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

/** The request the user authorizes in their kunji wallet (Security → Authorize an agent). */
export const agentRequest = (audience, scope) => ({
  kunjiCap: 'v1',
  audience,
  scope: scope && scope.length ? scope : ['login'],
  agentPub: agentPubB64(),
});

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
