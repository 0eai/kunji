/**
 * kunji agent live-demo module — kunji-agent-demo.js
 *
 * A BROWSER-side agent: it runs the full agentic-delegation flow client-side against the deployed
 * relay (app.kunji.cc) and a real relying party (kunji-demo.web.app), so the landing page can show a
 * genuinely live agent authorization — real OTP code + QR, real capability received & decrypted, real
 * login — and surface the raw I/O at each step. Nothing is mocked; nothing here ever sees kunji keys.
 *
 * It mirrors examples/kunji-mcp/capability-client.js / examples/kunji-agent-demo/agent-client.js (the
 * proven Node clients): Ed25519 holder-of-key proof via @noble/curves, ECDH P-256 + AES-GCM via
 * WebCrypto (same contract as src/lib/crypto), and the same v2 request shape. The agent keypair is
 * ephemeral (per run) — a demo never persists it.
 *
 * Usage (from the landing page, after the bundle loads):
 *   const run = window.kunjiAgentDemo.run({
 *     relayUrl: 'https://app.kunji.cc', rpBase: 'https://kunji-demo.web.app',
 *     audience: 'kunji-demo.web.app', scope: ['login'],
 *     qrEl: someElement,            // optional: a branded QR of the request is rendered here
 *     onStep: (ev) => { … },        // ev = { step, label, data? }
 *     signal: abortController.signal,
 *   });
 *   run.then(result => …);          // final { status, sub, scope, capabilityClaims, io }
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { renderBrandedQr } from '../../src/lib/brandedQr.js';

const subtle = globalThis.crypto.subtle;
const enc = (s) => new TextEncoder().encode(s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── base64 helpers (std + url) ──
const bytesToB64 = (bytes) => {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
};
const b64ToBytes = (b64) => {
  const s = atob(String(b64));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
};
const b64url = (b64) => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlFromBytes = (bytes) => b64url(bytesToB64(bytes));
const b64urlFromString = (s) => b64urlFromBytes(enc(s));
const b64urlToString = (s) => {
  let b = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  return new TextDecoder().decode(b64ToBytes(b));
};
const randHex = (n) => {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a, (x) => x.toString(16).padStart(2, '0')).join('');
};

// ── JWS (EdDSA) — byte-identical to capability.js signJWS so the RP verifier accepts the proof ──
const signJWS = (header, claims, sk) => {
  const input = `${b64urlFromString(JSON.stringify(header))}.${b64urlFromString(JSON.stringify(claims))}`;
  return `${input}.${b64urlFromBytes(ed25519.sign(enc(input), sk))}`;
};
const jwtPayload = (jwt) => JSON.parse(b64urlToString(String(jwt).split('.')[1]));

const post = (url, body) =>
  fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(
    (r) => r.json(),
  );

/**
 * Run the full agent flow. Emits onStep at each stage and resolves with the final result.
 * Throws if aborted, the relay/RP is unreachable, or the authorization expires.
 */
export const run = async ({
  relayUrl = 'https://app.kunji.cc',
  rpBase = 'https://kunji-demo.web.app',
  audience,
  scope = ['login'],
  qrEl = null,
  onStep = () => {},
  signal,
  pollMs = 2000,
  maxPolls = 150,
} = {}) => {
  const relay = relayUrl.replace(/\/$/, '');
  const base = rpBase.replace(/\/$/, '');
  const aud = audience || new URL(base).hostname;
  const aborted = () => signal && signal.aborted;
  const step = (s, label, data) => onStep({ step: s, label, data });

  // 1. Ephemeral agent Ed25519 key (holder-of-key) + ECDH transport key (encrypted return relay).
  const agentSk = ed25519.keygen().secretKey;
  const agentPub = bytesToB64(ed25519.getPublicKey(agentSk));
  const ecdh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  const transportPub = bytesToB64(await subtle.exportKey('spki', ecdh.publicKey));
  step('keygen', 'Generated the agent key + transport key', { agentPub });

  // 2. Build the v2 authorization request.
  const sessionId = randHex(32);
  const request = { kunjiCap: 'v2', audience: aud, scope, agentPub, transportPub, sessionId };
  step('request', 'Built the authorization request', { request });
  if (qrEl) renderBrandedQr(qrEl, { data: JSON.stringify(request), size: 200 });

  // 3. Register it with the relay → a 6-digit OTP code.
  const reg = await post(`${relay}/agent/request`, request);
  const code = /^\d{6}$/.test(String(reg.code)) ? reg.code : null;
  if (!code) throw new Error(reg.error === 'rate_limited' ? 'Relay rate-limited — wait a moment.' : 'Relay unavailable.');
  step('code', 'Got a 6-digit code from the relay', { code });

  // 4. Poll the relay for the wallet-deposited (ECDH-encrypted) capability.
  step('await', 'Waiting for you to approve in the wallet…');
  let deposited = null;
  for (let i = 0; i < maxPolls; i++) {
    if (aborted()) throw new Error('aborted');
    const r = await fetch(`${relay}/agent/capability?sessionId=${sessionId}`);
    if (r.status === 410) throw new Error('Authorization expired before approval.');
    if (r.ok) {
      deposited = await r.json(); // { walletPubE, encryptedCapability }
      break;
    }
    await sleep(pollMs); // 404 = not approved yet; 429 = backing off
  }
  if (!deposited) throw new Error('Timed out waiting for approval.');

  // 5. Decrypt the capability with the transport key (raw ECDH → AES-GCM, mirroring the wallet).
  const walletPub = await subtle.importKey('spki', b64ToBytes(deposited.walletPubE), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const aesKey = await subtle.deriveKey({ name: 'ECDH', public: walletPub }, ecdh.privateKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const { iv, data } = deposited.encryptedCapability;
  const ptBuf = await subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(iv) }, aesKey, b64ToBytes(data));
  const capability = JSON.parse(new TextDecoder().decode(ptBuf)); // wallet JSON-stringifies the JWT
  const capClaims = jwtPayload(capability);
  step('capability', 'Capability received & decrypted', {
    capabilityClaims: { sub: capClaims.sub, aud: capClaims.aud, scope: capClaims.scope, exp: capClaims.exp, jti: capClaims.jti },
    capability,
  });

  // 6. Log in to the RP: session → holder-of-key proof → /kunji/agent → status.
  const session = await post(`${base}/api/session`, { audience: aud, callbackUrl: `${base}/kunji/callback` });
  if (!session.sessionId) throw new Error('createSession failed.');
  step('session', 'Created a login session at the RP', { sessionId: session.sessionId, challenge: session.challenge });

  const agentProof = signJWS(
    { alg: 'EdDSA', typ: 'kunji-agentproof+jwt' },
    { aud, challenge: session.challenge, iat: Math.floor(Date.now() / 1000), jti: randHex(16), cap: capClaims.jti },
    agentSk,
  );
  step('proof', 'Signed the holder-of-key proof', { agentProof });

  const agentResponse = await post(`${base}/kunji/agent`, { sessionId: session.sessionId, capability, agentProof });
  step('login', 'Submitted to /kunji/agent', { agentResponse });

  const pollUrl = `https://us-central1-kunji-cc.cloudfunctions.net/getSessionStatus?sessionId=${session.sessionId}`;
  // kunji-demo.web.app polls the getSessionStatus function (its firebase rewrite maps /kunji/status too).
  const status = await fetch(`${base}/kunji/status?sessionId=${session.sessionId}`)
    .then((r) => (r.ok ? r.json() : fetch(pollUrl).then((x) => x.json())))
    .catch(() => fetch(pollUrl).then((x) => x.json()));
  step('status', 'Verified at the RP', { status });

  return {
    status: status.status,
    sub: status.sub || null,
    scope: status.scope || capClaims.scope || null,
    capabilityClaims: { sub: capClaims.sub, aud: capClaims.aud, scope: capClaims.scope, exp: capClaims.exp, jti: capClaims.jti },
    io: { request, code, capability, agentProof, agentResponse, status },
  };
};

// Render a branded QR of a request (string or object) into `el` — used by both the live flow and
// the recorded replay so the card skin can show the same QR the wallet would scan.
export const renderQr = (el, data) =>
  renderBrandedQr(el, { data: typeof data === 'string' ? data : JSON.stringify(data), size: 200 });

window.kunjiAgentDemo = { run, renderQr };
