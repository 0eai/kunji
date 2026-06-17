// kunji-agent-demo — the AGENT half of the flow (what a web-hosted agent or a headless script does).
//
// Mirrors examples/kunji-mcp/capability-client.js (the proven Node agent client) so this demo can
// authorize ITSELF through the live QR + OTP relay at app.kunji.cc, receive the capability over the
// encrypted return relay, then log in to THIS RP. The agent's Ed25519 key is persisted to .agent-key;
// the per-session ECDH transport key is kept in memory (the request carries only its public half).
// The user's kunji master/per-app keys are NEVER seen here. See ../../docs/agentic-delegation.md.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { buildAgentProof } from './capability.js';

// kunji app origin hosting the relay (agentRequestRelay + agentCapabilityPoll). Override for local dev.
const KUNJI_APP_URL = (process.env.KUNJI_APP_URL || 'https://app.kunji.cc').replace(/\/$/, '');
const KEYFILE = new URL('./.agent-key', import.meta.url);

// ── Persistent agent Ed25519 key (same .agent-key format agent-sim has always used: base64 secret) ──
const loadAgentKey = () => {
  let sk;
  if (existsSync(KEYFILE)) {
    sk = new Uint8Array(Buffer.from(readFileSync(KEYFILE, 'utf8').trim(), 'base64'));
  } else {
    ({ secretKey: sk } = ed25519.keygen());
    writeFileSync(KEYFILE, Buffer.from(sk).toString('base64'));
  }
  return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) };
};
export const agentPubB64 = () => Buffer.from(loadAgentKey().publicKey).toString('base64');

// ── ECDH P-256 + AES-GCM (mirrors src/lib/crypto/{ecdh,aes}.js + capability-client.js, via Node
// WebCrypto) so a capability the wallet ECDH-encrypts to our transport key decrypts here. ──
const subtle = globalThis.crypto.subtle;
const genECDH = () => subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
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
  subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
const aesGcmDecrypt = async ({ iv, data }, key) => {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(iv, 'base64') }, key, Buffer.from(data, 'base64'));
  return JSON.parse(Buffer.from(pt).toString('utf8')); // wallet JSON-stringifies the JWT; undo it
};

// Per-session transport private key (in memory; consumed on first successful poll).
const transportKeys = new Map(); // sessionId → pkcs8 b64

/** Build a v2 authorization request (+ an ephemeral ECDH transport key for the encrypted return relay). */
export const buildRequest = async (audience, scope) => {
  const { publicKey, privateKey } = await genECDH();
  const transportPub = await exportSpkiB64(publicKey);
  const sessionId = randomBytes(32).toString('hex');
  transportKeys.set(sessionId, await exportPkcs8B64(privateKey));
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
 * Build a PORTFOLIO request (4.2): ONE agent asking to be authorized at SEVERAL apps in one approval.
 * `apps` = [{ audience, scope }]. One shared ECDH transport key (its public half rides the request); each
 * app gets its own relay `sessionId` (the wallet deposits each per-app capability to its own session,
 * encrypted to the same transport key). Poll each with `pollCapability(item.sessionId)` / `awaitCapability`.
 */
export const buildPortfolioRequest = async (apps, label) => {
  const { publicKey, privateKey } = await genECDH();
  const transportPub = await exportSpkiB64(publicKey);
  const transportPriv = await exportPkcs8B64(privateKey);
  const items = (apps || []).map(({ audience, scope }) => {
    const sessionId = randomBytes(32).toString('hex');
    transportKeys.set(sessionId, transportPriv); // SAME transport key decrypts every item's session
    return { audience, scope: scope && scope.length ? scope : ['login'], sessionId };
  });
  const req = { kunjiCap: 'portfolio-v1', agentPub: agentPubB64(), transportPub, items };
  if (label) req.label = label;
  return req;
};

/** Decode a capability JWT's payload (no verification — for demo display of aud/scope/sub). */
export const decodeCapability = (jwt) => {
  try {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
};

/** Register the request with the live relay → a short 6-digit OTP code (best-effort; null on failure). */
export const postForCode = async (req) => {
  try {
    const resp = await fetch(`${KUNJI_APP_URL}/agent/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!resp.ok) return null;
    const { code } = await resp.json();
    return /^\d{6}$/.test(String(code)) ? code : null;
  } catch {
    return null;
  }
};

/** Terminal-renderable QR of the request JSON (the wallet scanner ingests it directly). */
export const terminalQr = async (req) => {
  try {
    const { default: QRCode } = await import('qrcode');
    return await QRCode.toString(JSON.stringify(req), { type: 'terminal', small: true });
  } catch {
    return null;
  }
};

/** Data-URI QR of the request JSON, for rendering in a browser <img> (CSP img-src data:). */
export const dataUriQr = async (req) => {
  try {
    const { default: QRCode } = await import('qrcode');
    return await QRCode.toDataURL(JSON.stringify(req), { margin: 1, width: 240 });
  } catch {
    return null;
  }
};

/**
 * Same-device deep link that opens the wallet STRAIGHT to the agent re-consent sheet
 * (push-relay.md Transport ①). The request isn't secret (public keys + scope), so it rides the
 * link inline as base64url JSON — `app.kunji.cc/?authorize=…`. The RP nudges the user through its
 * own UI ("tap to approve in kunji") and this is the link it sends; no new kunji infra.
 */
export const authorizeDeepLink = (req) =>
  `${KUNJI_APP_URL}/?authorize=${Buffer.from(JSON.stringify(req)).toString('base64url')}`;

/**
 * Step-up: ask the user for a BROADER scope on an app this agent is already connected to (after an
 * `insufficient_scope` 403). Builds a fresh request (new transport key + sessionId), registers it
 * for an OTP code, and returns the code + QR + the deep link. Await the new, broader capability with
 * `awaitCapability(sessionId)` exactly like the first authorization — then re-`login` and retry.
 */
export const stepUp = async (audience, scope) => {
  const req = await buildRequest(audience, scope);
  const [code, qr] = await Promise.all([postForCode(req), terminalQr(req)]);
  return { req, sessionId: req.sessionId, code, qr, deepLink: authorizeDeepLink(req) };
};

/**
 * Step-up via the push relay (push-relay.md Transport ②): for a channel-less agent the user enabled
 * notifications for. Deposit a step-up request (→ a 6-digit relay code = the opaque pointer), then ping
 * the wallet's `channelId` via /push/dispatch with a holder-of-key proof. The wallet's notification
 * fires; the user approves; the broader capability comes back over the return relay. `channelId` is the
 * value the wallet showed at authorization. Then `awaitCapability(sessionId)` + `login` as usual.
 */
export const requestViaPush = async (channelId, audience, scope) => {
  const req = await buildRequest(audience, scope); // stores the per-session transport key
  const requestId = await postForCode(req); // the agent-request relay code = the push pointer
  if (!requestId) throw new Error('could not deposit the step-up request');
  const { secretKey } = loadAgentKey();
  const proof = buildAgentProof(secretKey, { audience: channelId, challenge: requestId, capJti: channelId });
  const resp = await fetch(`${KUNJI_APP_URL}/push/dispatch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ channelId, requestId, proof }),
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error('push dispatch failed: ' + (e.error || resp.status));
  }
  return { requestId, sessionId: req.sessionId };
};

/**
 * Poll the relay ONCE for the wallet-deposited capability; returns the JWT string, or null if the
 * user hasn't approved yet (404/429). Throws on an expired authorization (410) or unknown session.
 * Decrypts with the per-session transport key (consumed on success).
 */
export const pollCapability = async (sessionId) => {
  const transportPriv = transportKeys.get(sessionId);
  if (!transportPriv) throw new Error('unknown_session');
  const resp = await fetch(`${KUNJI_APP_URL}/agent/capability?sessionId=${sessionId}`);
  if (resp.status === 410) throw new Error('authorization_expired');
  if (!resp.ok) return null; // 404 = not approved yet; 429 = backing off
  const { walletPubE, encryptedCapability } = await resp.json();
  const priv = await importPkcs8(transportPriv);
  const shared = await deriveShared(priv, await importSpki(walletPubE));
  const capability = await aesGcmDecrypt(encryptedCapability, shared);
  transportKeys.delete(sessionId);
  return capability;
};

/** Headless: poll until approved (or time out). */
export const awaitCapability = async (sessionId, { tries = 100, intervalMs = 3000 } = {}) => {
  for (let i = 0; i < tries; i++) {
    const cap = await pollCapability(sessionId);
    if (cap) return cap;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('timed_out');
};

/**
 * Log in to THIS RP with the capability: create a session, sign its challenge with the agent key
 * (holder-of-key), POST /kunji/agent, read /kunji/status. Returns the round-trip I/O for display.
 */
export const login = async (baseUrl, capability) => {
  const base = String(baseUrl).replace(/\/$/, '');
  const audience = new URL(base).hostname;
  const post = (p, body) =>
    fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(
      (r) => r.json(),
    );
  const capJti = JSON.parse(Buffer.from(capability.split('.')[1], 'base64url').toString('utf8')).jti;
  const session = await post('/api/session', { audience, callbackUrl: `${base}/kunji/callback` });
  if (!session.sessionId) throw new Error('createSession failed: ' + JSON.stringify(session));
  const { secretKey } = loadAgentKey();
  const agentProof = buildAgentProof(secretKey, { audience, challenge: session.challenge, capJti });
  const agentResp = await post('/kunji/agent', { sessionId: session.sessionId, capability, agentProof });
  const status = await fetch(`${base}/kunji/status?sessionId=${session.sessionId}`).then((r) => r.json());
  return { agentResp, status, agentProof, sessionId: session.sessionId, challenge: session.challenge };
};
