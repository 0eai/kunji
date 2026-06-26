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
  pollMs = 3000,
  maxPolls = 100,
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

  // 4. Poll the relay for the wallet-deposited (ECDH-encrypted) capability. Poll slowly enough
  // (3s = 20/min) to stay under the endpoint's per-IP limit across the whole approval window —
  // otherwise a 429 mid-wait would read as "still pending" forever, even after you approve.
  step('await', 'Waiting for you to approve in the wallet…');
  let deposited = null;
  let warned429 = false;
  for (let i = 0; i < maxPolls; i++) {
    if (aborted()) throw new Error('aborted');
    const r = await fetch(`${relay}/agent/capability?sessionId=${sessionId}`);
    if (r.status === 410) throw new Error('Authorization expired before approval.');
    if (r.ok) {
      deposited = await r.json(); // { walletPubE, encryptedCapability }
      break;
    }
    if (r.status === 429) {
      // Back off so we recover instead of hammering — and surface it, never silent.
      if (!warned429) {
        step('await', 'Relay busy — backing off, still waiting…');
        warned429 = true;
      }
      await sleep(pollMs * 2);
      continue;
    }
    await sleep(pollMs); // 404 = not approved yet
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

// ── Step-up (push-relay.md Transport ①) ───────────────────────────────────────────────────────────
// One authorize round: build a v2 request for `scope` bound to `agentSk`, register it (→ 6-digit code +
// same-device deep link), poll the relay for the wallet-deposited capability, and decrypt it. Reused
// across both rounds of runStepUp with ONE agentSk so the wallet recognizes the same agent and shows a
// DELTA re-consent on the second round.
const authorizeRound = async ({ relay, aud, scope, agentSk, round, onStep, signal, pollMs, maxPolls }) => {
  const aborted = () => signal && signal.aborted;
  const step = (s, label, data) => onStep({ step: s, label, data: { round, ...data } });
  const ecdh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  const transportPub = bytesToB64(await subtle.exportKey('spki', ecdh.publicKey));
  const agentPub = bytesToB64(ed25519.getPublicKey(agentSk));
  const sessionId = randHex(32);
  const request = { kunjiCap: 'v2', audience: aud, scope, agentPub, transportPub, sessionId };
  const deepLink = `${relay}/?authorize=${b64urlFromString(JSON.stringify(request))}`;
  step('request', 'Built the authorization request', { request, deepLink });

  const reg = await post(`${relay}/agent/request`, request);
  const code = /^\d{6}$/.test(String(reg.code)) ? reg.code : null;
  if (!code) throw new Error(reg.error === 'rate_limited' ? 'Relay rate-limited — wait a moment.' : 'Relay unavailable.');
  step('code', 'Got a 6-digit code from the relay', { code, deepLink, request });

  step('await', 'Waiting for you to approve in the wallet…');
  let deposited = null;
  let warned429 = false;
  for (let i = 0; i < maxPolls; i++) {
    if (aborted()) throw new Error('aborted');
    const r = await fetch(`${relay}/agent/capability?sessionId=${sessionId}`);
    if (r.status === 410) throw new Error('Authorization expired before approval.');
    if (r.ok) { deposited = await r.json(); break; }
    if (r.status === 429) {
      if (!warned429) { step('await', 'Relay busy — backing off, still waiting…'); warned429 = true; }
      await sleep(pollMs * 2);
      continue;
    }
    await sleep(pollMs);
  }
  if (!deposited) throw new Error('Timed out waiting for approval.');

  const walletPub = await subtle.importKey('spki', b64ToBytes(deposited.walletPubE), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const aesKey = await subtle.deriveKey({ name: 'ECDH', public: walletPub }, ecdh.privateKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const { iv, data } = deposited.encryptedCapability;
  const ptBuf = await subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(iv) }, aesKey, b64ToBytes(data));
  const capability = JSON.parse(new TextDecoder().decode(ptBuf));
  const capClaims = jwtPayload(capability);
  // If the user enabled notifications, the wallet also delivered the opaque push channel id over this same
  // encrypted return relay — decrypt it so a push step-up needs no manual copy/paste.
  let channelId = null;
  if (deposited.encryptedChannel?.iv) {
    try {
      const cb = await subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(deposited.encryptedChannel.iv) },
        aesKey,
        b64ToBytes(deposited.encryptedChannel.data),
      );
      channelId = JSON.parse(new TextDecoder().decode(cb));
    } catch {
      /* no channel delivered / undecodable — caller falls back to manual entry */
    }
  }
  step('capability', 'Capability received & decrypted', {
    capabilityClaims: { sub: capClaims.sub, aud: capClaims.aud, scope: capClaims.scope, exp: capClaims.exp, jti: capClaims.jti },
  });
  return { capability, capClaims, channelId };
};

// Log in to the RP with a capability (session → holder-of-key proof → /kunji/agent → status).
const loginRound = async ({ base, aud, agentSk, capability, capClaims, round, onStep }) => {
  const step = (s, label, data) => onStep({ step: s, label, data: { round, ...data } });
  const session = await post(`${base}/api/session`, { audience: aud, callbackUrl: `${base}/kunji/callback` });
  if (!session.sessionId) throw new Error('createSession failed.');
  const agentProof = signJWS(
    { alg: 'EdDSA', typ: 'kunji-agentproof+jwt' },
    { aud, challenge: session.challenge, iat: Math.floor(Date.now() / 1000), jti: randHex(16), cap: capClaims.jti },
    agentSk,
  );
  const agentResponse = await post(`${base}/kunji/agent`, { sessionId: session.sessionId, capability, agentProof });
  const status = await fetch(`${base}/kunji/status?sessionId=${session.sessionId}`).then((r) => r.json()).catch(() => ({}));
  step('login', 'Logged in at the RP', { agentResponse, status, scope: status.scope || capClaims.scope });
  return { rpSessionId: session.sessionId, status };
};

const getJson = async (url) => {
  const r = await fetch(url);
  let body = {};
  try { body = await r.json(); } catch { /* non-JSON */ }
  return { status: r.status, body };
};

/**
 * A stateful step-up session that keeps ONE agent key across many rounds, so the wallet recognizes the same
 * agent and shows a DELTA re-consent ("already granted" for prior scopes) each time. Drives an on-demand
 * "step up again" UI: call `authorize(scope)` repeatedly with a growing scope set; each is one approval.
 */
export const createStepUpSession = ({
  relayUrl = 'https://app.kunji.cc',
  rpBase = 'https://kunji-demo.web.app',
  audience,
  pollMs = 3000,
  maxPolls = 100,
} = {}) => {
  const relay = relayUrl.replace(/\/$/, '');
  const base = rpBase.replace(/\/$/, '');
  const aud = audience || new URL(base).hostname;
  const agentSk = ed25519.keygen().secretKey; // ONE key for the whole session → the wallet sees one agent
  let round = 0;
  let scope = [];
  return {
    agentPub: bytesToB64(ed25519.getPublicKey(agentSk)),
    scope: () => scope.slice(),
    // Authorize the agent for the full `nextScope` set (one delta approval in the wallet); returns the new
    // capability claims + the RP login session. Reuses the session's agent key across rounds.
    authorize: async (nextScope, { onStep = () => {}, signal } = {}) => {
      round += 1;
      scope = nextScope;
      const opts = { relay, base, aud, agentSk, onStep, signal, pollMs, maxPolls };
      const r = await authorizeRound({ ...opts, scope: nextScope, round });
      const l = await loginRound({ ...opts, capability: r.capability, capClaims: r.capClaims, round });
      return { capClaims: r.capClaims, status: l.status, rpSessionId: l.rpSessionId, scope: nextScope };
    },
    // Call the RP's scope-gated demo action (read:profile) with a login session.
    callProfile: (rpSessionId) => getJson(`${base}/api/profile?sessionId=${rpSessionId}`),
  };
};

/**
 * Step-up demo (Transport ①): connect at `['login']`, hit a scope-gated RP action (`/api/profile`),
 * get a 403 insufficient_scope, then re-authorize the SAME agent at `['login', need]` — the wallet
 * shows a DELTA re-consent — and retry the action to a 200. Two real approvals in your wallet.
 */
export const runStepUp = async ({
  relayUrl = 'https://app.kunji.cc',
  rpBase = 'https://kunji-demo.web.app',
  audience,
  onStep = () => {},
  signal,
  pollMs = 3000,
  maxPolls = 100,
} = {}) => {
  const relay = relayUrl.replace(/\/$/, '');
  const base = rpBase.replace(/\/$/, '');
  const aud = audience || new URL(base).hostname;
  const step = (s, label, data) => onStep({ step: s, label, data });

  const agentSk = ed25519.keygen().secretKey; // ONE key across both rounds → the wallet sees one agent
  step('keygen', 'Generated the agent key', { agentPub: bytesToB64(ed25519.getPublicKey(agentSk)) });

  // Round 1 — connect with the narrow `login` scope.
  const opts = { relay, base, aud, agentSk, onStep, signal, pollMs, maxPolls };
  const r1 = await authorizeRound({ ...opts, scope: ['login'], round: 1 });
  const l1 = await loginRound({ ...opts, capability: r1.capability, capClaims: r1.capClaims, round: 1 });

  // Hit the scope-gated resource → expect 403 insufficient_scope.
  let gated = await getJson(`${base}/api/profile?sessionId=${l1.rpSessionId}`);
  if (gated.status === 200) {
    step('gated-ok', 'Gated action already allowed', { profile: gated.body.profile });
    return { status: 'approved', scope: l1.status.scope, profile: gated.body.profile, steppedUp: false };
  }
  const need = gated.body?.need || 'read:profile';
  step('gated-denied', `403 insufficient_scope — needs "${need}"`, { status: gated.status, need });

  // Round 2 — step up: re-authorize the SAME agent for the broader scope (wallet shows the delta).
  step('stepup', `Requesting the extra scope "${need}" — approve the delta in your wallet`, { need });
  const r2 = await authorizeRound({ ...opts, scope: ['login', need], round: 2 });
  const l2 = await loginRound({ ...opts, capability: r2.capability, capClaims: r2.capClaims, round: 2 });

  // Retry the gated action → now 200.
  gated = await getJson(`${base}/api/profile?sessionId=${l2.rpSessionId}`);
  step('gated-ok', `Retried /api/profile → ${gated.status}`, { status: gated.status, profile: gated.body.profile });
  return {
    status: l2.status.status || 'approved',
    scope: l2.status.scope || r2.capClaims.scope || null,
    profile: gated.body.profile || null,
    steppedUp: true,
    io: { need, round1: r1.capClaims, round2: r2.capClaims, profile: gated.body },
  };
};

/**
 * Push step-up demo (push-relay.md Transport ②): connect the agent at `['login']` (the user approves AND
 * turns on "Notify me" in the wallet, which registers this agent as a push poster + reveals a channel id),
 * then step up via WEB PUSH — the agent pings the channel, the wallet shows a notification, and the user
 * approves the delta. ONE agent key across both rounds so the wallet recognizes the same agent and the
 * holder-of-key proof matches the registered poster key. `getChannelId` is an async callback the UI resolves
 * from a paste field (the channel id the wallet showed). Mirrors the Node `requestViaPush` + `awaitCapability`.
 */
export const runPushStepUp = async ({
  relayUrl = 'https://app.kunji.cc',
  rpBase = 'https://kunji-demo.web.app',
  audience,
  getChannelId,
  onStep = () => {},
  signal,
  pollMs = 3000,
  maxPolls = 100,
} = {}) => {
  const relay = relayUrl.replace(/\/$/, '');
  const base = rpBase.replace(/\/$/, '');
  const aud = audience || new URL(base).hostname;
  const aborted = () => signal && signal.aborted;
  const step = (s, label, data) => onStep({ step: s, label, data });

  const agentSk = ed25519.keygen().secretKey; // ONE key: authorize → push proof must match the poster key
  const agentPub = bytesToB64(ed25519.getPublicKey(agentSk));
  step('keygen', 'Generated the agent key', { agentPub });

  // Round 1 — connect at `login` (Transport ①). The UI tells the user to ALSO toggle "Notify me" ON, which
  // makes the wallet deliver the push channel id back over the encrypted relay (decoded by authorizeRound).
  const opts = { relay, base, aud, agentSk, onStep, signal, pollMs, maxPolls };
  const r1 = await authorizeRound({ ...opts, scope: ['login'], round: 1 });
  await loginRound({ ...opts, capability: r1.capability, capClaims: r1.capClaims, round: 1 });

  // Prefer the auto-delivered channel id (no copy/paste); fall back to asking the UI for it (older wallets,
  // or if the user didn't enable notifications during round 1).
  let channelId = r1.channelId && /^[0-9a-f]{64}$/i.test(r1.channelId) ? r1.channelId : null;
  if (channelId) {
    step('channel', 'Received the push channel automatically — no copy/paste', { channelId });
  } else {
    if (typeof getChannelId !== 'function') throw new Error('No channel id (enable “Notify me” in the wallet).');
    step('need-channel', 'Turn on “Notify me” in the wallet, then paste the channel id it shows');
    channelId = String((await getChannelId()) || '').trim();
    if (!/^[0-9a-f]{64}$/i.test(channelId)) throw new Error('That doesn’t look like a channel id (64 hex).');
  }

  // Round 2 — step up via PUSH. Deposit a v2 request bound to the SAME agent key → a 6-digit relay code (the
  // opaque push pointer); ping the channel with a holder-of-key proof; await the deposited capability.
  const ecdh = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  const transportPub = bytesToB64(await subtle.exportKey('spki', ecdh.publicKey));
  const sessionId = randHex(32);
  const request = { kunjiCap: 'v2', audience: aud, scope: ['login', 'read:profile'], agentPub, transportPub, sessionId };
  const reg = await post(`${relay}/agent/request`, request);
  const requestId = /^\d{6}$/.test(String(reg.code)) ? reg.code : null;
  if (!requestId) throw new Error(reg.error === 'rate_limited' ? 'Relay rate-limited — wait a moment.' : 'Relay unavailable.');

  const proof = signJWS(
    { alg: 'EdDSA', typ: 'kunji-agentproof+jwt' },
    { aud: channelId, challenge: requestId, iat: Math.floor(Date.now() / 1000), jti: randHex(16), cap: channelId },
    agentSk,
  );
  const disp = await post(`${relay}/push/dispatch`, { channelId, requestId, proof });
  if (disp.error)
    throw new Error(
      disp.error === 'not_found'
        ? 'Channel not found — enable notifications for this app in the wallet first.'
        : disp.error === 'bad_proof'
          ? 'Push rejected — the wallet hasn’t authorized this agent to push (re-enable “Notify me”).'
          : 'Push dispatch failed: ' + disp.error,
    );
  step('dispatched', 'Pushed to the wallet — approve the notification', { requestId, delivered: disp.delivered });

  step('await', 'Waiting for you to approve the notification…');
  let deposited = null;
  let warned429 = false;
  for (let i = 0; i < maxPolls; i++) {
    if (aborted()) throw new Error('aborted');
    const r = await fetch(`${relay}/agent/capability?sessionId=${sessionId}`);
    if (r.status === 410) throw new Error('Authorization expired before approval.');
    if (r.ok) { deposited = await r.json(); break; }
    if (r.status === 429) { if (!warned429) { step('await', 'Relay busy — backing off, still waiting…'); warned429 = true; } await sleep(pollMs * 2); continue; }
    await sleep(pollMs);
  }
  if (!deposited) throw new Error('Timed out waiting for approval.');

  const walletPub = await subtle.importKey('spki', b64ToBytes(deposited.walletPubE), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const aesKey = await subtle.deriveKey({ name: 'ECDH', public: walletPub }, ecdh.privateKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const { iv, data } = deposited.encryptedCapability;
  const ptBuf = await subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(iv) }, aesKey, b64ToBytes(data));
  const capability = JSON.parse(new TextDecoder().decode(ptBuf));
  const capClaims = jwtPayload(capability);
  step('capability', 'Capability received & decrypted', {
    capabilityClaims: { sub: capClaims.sub, aud: capClaims.aud, scope: capClaims.scope, exp: capClaims.exp, jti: capClaims.jti },
  });

  const l2 = await loginRound({ ...opts, capability, capClaims, round: 2 });
  const gated = await getJson(`${base}/api/profile?sessionId=${l2.rpSessionId}`);
  step('gated-ok', `GET /api/profile → ${gated.status} — released`, { status: gated.status, profile: gated.body.profile });
  return {
    status: l2.status.status || 'approved',
    scope: l2.status.scope || capClaims.scope || null,
    profile: gated.body.profile || null,
    via: 'push',
    steppedUp: true,
    io: { channelId, requestId, round2: capClaims, profile: gated.body },
  };
};

// Render a branded QR of a request (string or object) into `el` — used by both the live flow and
// the recorded replay so the card skin can show the same QR the wallet would scan.
export const renderQr = (el, data) =>
  renderBrandedQr(el, { data: typeof data === 'string' ? data : JSON.stringify(data), size: 200 });

window.kunjiAgentDemo = { run, runStepUp, runPushStepUp, createStepUpSession, renderQr };
