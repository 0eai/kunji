/**
 * "Sign in with kunji" — a framework-free, Firebase-free relying party that accepts BOTH
 * human logins (the §6 discoverable-login assertion) AND agent logins (a holder-of-key
 * capability minted by the user's wallet — agentic delegation, docs/agentic-delegation.md).
 *
 * Plain Node `http` + an in-memory session Map + two verifiers: verify.js (§6 assertion) and
 * capability.js (the EdDSA-JWT capability). There is NO kunji server in the login path — the
 * wallet POSTs straight to /kunji/callback, and an agent POSTs straight to /kunji/agent.
 *
 * Endpoints (the agent endpoint is the only addition over kunji-node-demo):
 *   POST /api/session    → { sessionId, challenge, audience, callbackUrl, expiresAt, code }
 *   POST /kunji/callback ← a HUMAN's signed assertion; runs §6 verification
 *   POST /kunji/agent    ← an AGENT's { sessionId, capability, agentProof }; capability + proof
 *   GET  /kunji/status?sessionId= → { status, sub, claims, scope, agent }
 *   GET  /kunji/session?code=     → resolve a 6-digit OTP code → its pending session (rate-limited)
 *   GET  /*              → the static frontend (public/index.html)
 *
 * Swapping the Map for Postgres/Redis and `http` for Express is a 1:1 mapping.
 */
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyAssertion } from './verify.js';
import { verifyCapabilityAssertion, scopeSatisfies } from './capability.js';
import { buildRequest, postForCode, dataUriQr, pollCapability, login as agentLogin } from './agent-client.js';

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 2 * 60 * 1000;
const __dirname = dirname(fileURLToPath(import.meta.url));
// base64url session id / challenge — ~30% shorter than hex (leaner QR), same entropy.
const token = (n) => randomBytes(n).toString('base64url');

// In-memory store. A real RP uses its own DB; the shape is the same.
const sessions = new Map(); // sessionId → { challenge, audience, callbackUrl, status, sub, claims, scope, agent, code, expiresAt }
const codeToSession = new Map(); // 6-digit OTP code → sessionId (so the wallet can resolve by code)
const sweep = () => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now > s.expiresAt + 5 * 60_000) {
      sessions.delete(id);
      if (s.code) codeToSession.delete(s.code);
    }
  }
};

// A 6-digit OTP code unique among active sessions (so the wallet's "Sign in with a code" works
// without scanning). The code space is small — the lookup below is rate-limited. Demo-grade; see
// examples/kunji-login-demo + the S5 audit note for the production lens (per-code attempt cap, etc.).
const allocCode = () => {
  for (let i = 0; i < 12; i++) {
    const code = String(100000 + (randomBytes(4).readUInt32BE(0) % 900000)); // always 6 digits
    if (!codeToSession.has(code)) return code;
  }
  return null; // give up — astronomically unlikely; the QR still works
};

// In-memory rate limit for the code lookup: per-IP sliding window + a global failed-lookup cap.
const LOOKUP_MAX = 10;
const LOOKUP_WINDOW = 60_000;
const ipHits = new Map(); // ip → { start, count }
let globalFails = { start: 0, count: 0 };
const clientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
const rateLimited = (ip) => {
  const now = Date.now();
  const d = ipHits.get(ip);
  if (!d || now - d.start > LOOKUP_WINDOW) {
    ipHits.set(ip, { start: now, count: 1 });
    return false;
  }
  if (d.count >= LOOKUP_MAX) return true;
  d.count += 1;
  return false;
};
const globalFailExceeded = () => {
  if (Date.now() - globalFails.start > LOOKUP_WINDOW) globalFails = { start: Date.now(), count: 0 };
  return globalFails.count >= 60;
};
const bumpGlobalFail = () => {
  if (Date.now() - globalFails.start > LOOKUP_WINDOW) globalFails = { start: Date.now(), count: 0 };
  globalFails.count += 1;
};

// Operator revocation denylist (a capability jti the RP refuses). Mirrors the Firestore
// `revokedCapabilities` collection the Firebase demo reads. Empty here — populate it from your
// own out-of-band signal. The capability's short TTL is the backstop. We skip the kunji-hosted,
// issuer-signed `getRevocation` path (it needs a fetch to app.kunji.cc) — out of scope for a
// zero-infra local demo; see examples/kunji-login-demo for that variant.
const revoked = new Set();

// Web "Authorize an agent" flow: this server acts as a web-hosted AGENT. It asks the live relay
// (app.kunji.cc) for a 6-digit code + QR, the user authorizes in their wallet, the capability comes
// back over the encrypted relay, and the server logs itself in here. Per-sessionId bookkeeping:
const agentBase = new Map(); // sessionId → this RP's base origin (for the eventual login)
const agentResults = new Map(); // sessionId → the finished {status, sub, …, io} (so repeat polls are idempotent)
const HEX64 = /^[0-9a-f]{64}$/i;

const json = (res, code, body) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
};

// Security headers for the served frontend. The CSP keeps `script-src` tight (no
// 'unsafe-inline') — that's why the page script lives in an external /app.js.
const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self' https://kunji.cc; connect-src 'self'; " +
    "img-src 'self' https: data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
};
const readBody = (req) =>
  new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 256 * 1024) req.destroy(); // hard cap
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(data || '{}'));
      } catch {
        resolve(null);
      }
    });
  });

// Derive OUR audience + callback from the request host — the server is authoritative
// (never trust client-supplied values, spec §11). Behind a proxy/tunnel, honor x-forwarded-*;
// set PUBLIC_ORIGIN to pin them explicitly (e.g. PUBLIC_ORIGIN=https://demo.example.com).
const originOf = (req) => {
  if (process.env.PUBLIC_ORIGIN) {
    const u = new URL(process.env.PUBLIC_ORIGIN);
    return { audience: u.hostname, callbackUrl: `${u.origin}/kunji/callback` };
  }
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  // Real scheme: forwarded header (tunnel/proxy) → else whether this socket is TLS.
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  return { audience: host.split(':')[0], callbackUrl: `${proto}://${host}/kunji/callback` };
};

const handler = async (req, res) => {
  // CORS: the wallet (app.kunji.cc) POSTs the assertion cross-origin, and the JSON
  // content-type triggers a preflight. The security is in the signed assertion + session,
  // not the origin, so `*` is fine for the callback. (The Firebase demo used cors:true.)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    // Private Network Access: a public page (app.kunji.cc) calling a private LAN IP must
    // be granted, or Chrome blocks the wallet's POST. Harmless when not on a LAN.
    if (req.headers['access-control-request-private-network'])
      res.setHeader('Access-Control-Allow-Private-Network', 'true');
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, 'http://x');
  const path = url.pathname;

  // 1. Create a session (the widget and the agent both call this first).
  if (req.method === 'POST' && path === '/api/session') {
    sweep();
    const { audience, callbackUrl } = originOf(req);
    const sessionId = token(16);
    const challenge = token(32);
    const code = allocCode(); // 6-digit OTP alternative to scanning
    const expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(sessionId, {
      challenge,
      audience,
      callbackUrl,
      status: 'pending',
      sub: null,
      claims: null,
      scope: null,
      agent: false,
      code,
      expiresAt,
    });
    if (code) codeToSession.set(code, sessionId);
    return json(res, 200, { sessionId, challenge, audience, callbackUrl, expiresAt, code });
  }

  // 2a. A HUMAN's wallet POSTs the signed assertion here. Verify + consume atomically.
  if (req.method === 'POST' && path === '/kunji/callback') {
    const assertion = await readBody(req);
    const sessionId = assertion?.signedPayload?.sessionId;
    const session = sessionId ? sessions.get(sessionId) : null;
    const r = verifyAssertion({ assertion, session, audience: session?.audience });
    if (!r.ok) return json(res, 400, { error: r.error });
    // single-use: re-check + flip in one tick (single-threaded, so this is atomic here)
    if (session.status !== 'pending') return json(res, 400, { error: 'session_consumed' });
    session.status = 'approved';
    session.sub = r.sub;
    session.claims = r.claims;
    return json(res, 200, { status: 'ok' });
  }

  // 2b. An AGENT presents a capability (minted by the user's wallet) + a holder-of-key proof
  // for this session's challenge. Verified locally like §6, but the principal acts via a
  // scoped, expiring, revocable capability instead of a fresh human approval. The single
  // threaded event loop gives the same check-then-flip atomicity /kunji/callback relies on.
  // See docs/agentic-delegation.md.
  if (req.method === 'POST' && path === '/kunji/agent') {
    const { sessionId, capability, agentProof } = (await readBody(req)) || {};
    if (!sessionId || !capability || !agentProof)
      return json(res, 400, { error: 'malformed_request' });
    const session = sessions.get(sessionId);
    if (!session) return json(res, 400, { error: 'unknown_session' });
    if (Date.now() > session.expiresAt) return json(res, 400, { error: 'session_expired' });
    const r = await verifyCapabilityAssertion({
      capability,
      agentProof,
      audience: session.audience,
      challenge: session.challenge,
      isRevoked: (jti) => revoked.has(String(jti)),
    });
    if (!r.ok) return json(res, 400, { error: r.error });
    if (session.status !== 'pending') return json(res, 400, { error: 'session_consumed' });
    session.status = 'approved';
    session.sub = r.sub;
    session.scope = r.scope;
    session.agent = true; // distinguish an agent login from a human one in /kunji/status
    return json(res, 200, { status: 'ok' });
  }

  // 3. The widget/frontend polls this until approved.
  if (req.method === 'GET' && path === '/kunji/status') {
    const s = sessions.get(url.searchParams.get('sessionId') || '');
    if (!s) return json(res, 404, { error: 'unknown_session' });
    return json(res, 200, { status: s.status, sub: s.sub, claims: s.claims, scope: s.scope, agent: s.agent });
  }

  // 3c. A scope-GATED resource: returns the (demo) profile ONLY if the approved session's scope
  // satisfies `read:profile`. Proves backendless scope enforcement (docs/scope.md) using the same
  // scopeSatisfies the wallet uses. The sessionId is this demo's bearer handle (as elsewhere here).
  if (req.method === 'GET' && path === '/api/profile') {
    const s = sessions.get(url.searchParams.get('sessionId') || '');
    if (!s || s.status !== 'approved') return json(res, 401, { error: 'not_authenticated' });
    if (!scopeSatisfies(s.scope, [{ id: 'read:profile' }]))
      return json(res, 403, { error: 'insufficient_scope', need: 'read:profile', have: s.scope });
    return json(res, 200, { sub: s.sub, profile: { plan: 'pro', since: 2024 } });
  }

  // 3b. Resolve a 6-digit OTP code → its pending session, so the wallet can sign without scanning
  // (the wallet's lookupSessionByCode → GET https://{audience}/kunji/session?code=). Returns the
  // same fields parseQRPayload yields. Rate-limited; reject malformed input before the limiter.
  if (req.method === 'GET' && path === '/kunji/session') {
    const code = url.searchParams.get('code') || '';
    if (!/^\d{6}$/.test(code)) return json(res, 400, { error: 'bad_code' });
    if (rateLimited(clientIp(req)) || globalFailExceeded())
      return json(res, 429, { error: 'rate_limited' });
    sweep();
    const sessionId = codeToSession.get(code);
    const s = sessionId && sessions.get(sessionId);
    if (!s || s.status !== 'pending') {
      bumpGlobalFail();
      return json(res, 404, { error: 'invalid_code' });
    }
    if (Date.now() > s.expiresAt) return json(res, 410, { error: 'expired_code' });
    return json(res, 200, {
      sessionId,
      challenge: s.challenge,
      audience: s.audience,
      callbackUrl: s.callbackUrl,
      expiresAt: s.expiresAt,
    });
  }

  // 3c. Web "Authorize an agent": the server (as a web-hosted agent) gets a 6-digit code + QR from
  // the live relay for the user to authorize in their wallet. The browser shows the code/QR and polls.
  if (req.method === 'POST' && path === '/agent/start') {
    const { audience, callbackUrl } = originOf(req);
    const base = callbackUrl.replace(/\/kunji\/callback$/, '');
    const request = await buildRequest(audience, ['login']);
    const [code, qrDataUri] = await Promise.all([postForCode(request), dataUriQr(request)]);
    agentBase.set(request.sessionId, base);
    // `request` is not secret (public keys + scope) — safe to echo so the browser can display it.
    return json(res, 200, { sessionId: request.sessionId, code, qrDataUri, request });
  }

  // 3d. The browser polls this. The server polls the relay once; on the wallet's approval it
  // decrypts the capability and logs itself in here, returning the verified id + the raw round-trip
  // I/O (so the demo can show developers exactly what crossed the wire).
  if (req.method === 'GET' && path === '/agent/poll') {
    const sessionId = url.searchParams.get('sessionId') || '';
    if (!HEX64.test(sessionId)) return json(res, 400, { error: 'bad_session' });
    const cached = agentResults.get(sessionId);
    if (cached) return json(res, 200, cached);
    let capability;
    try {
      capability = await pollCapability(sessionId);
    } catch (e) {
      // Terminal: the relay session expired, or we lost the transport key (server restart). Cache it.
      // Anything else (a network blip) → report pending so the browser keeps polling, don't cache.
      if (e.message === 'authorization_expired' || e.message === 'unknown_session') {
        const out = { status: 'error', error: e.message };
        agentResults.set(sessionId, out);
        return json(res, 200, out);
      }
      return json(res, 200, { status: 'pending' });
    }
    if (!capability) return json(res, 200, { status: 'pending' });
    const base = agentBase.get(sessionId) || `http://localhost:${PORT}`;
    const r = await agentLogin(base, capability);
    const claims = JSON.parse(Buffer.from(capability.split('.')[1], 'base64url').toString('utf8'));
    const out = {
      status: r.status?.status === 'approved' ? 'approved' : 'failed',
      sub: r.status?.sub || null,
      scope: r.status?.scope || null,
      capabilityClaims: { sub: claims.sub, aud: claims.aud, scope: claims.scope, exp: claims.exp, jti: claims.jti },
      io: { capability, agentProof: r.agentProof, agentResponse: r.agentResp, status: r.status },
    };
    agentResults.set(sessionId, out);
    return json(res, 200, out);
  }

  // 4. Static frontend + its externalized script.
  if (req.method === 'GET' && path === '/app.js') {
    try {
      const js = readFileSync(join(__dirname, 'public', 'app.js'));
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', ...SECURITY_HEADERS });
      return res.end(js);
    } catch {
      return json(res, 404, { error: 'not_found' });
    }
  }
  if (req.method === 'GET') {
    try {
      const html = readFileSync(join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS });
      return res.end(html);
    } catch {
      return json(res, 500, { error: 'no_frontend' });
    }
  }

  json(res, 405, { error: 'method_not_allowed' });
};

// Serve HTTPS when given a key + cert (e.g. from mkcert), else plain HTTP. A real wallet
// requires HTTPS for any non-localhost host, and the cert must be TRUSTED by the connecting
// device — a self-signed cert is rejected by the wallet's fetch. Use mkcert (a locally-
// trusted CA you install on your devices) or a tunnel for a publicly-trusted cert.
const TLS = process.env.TLS_KEY && process.env.TLS_CERT;
const scheme = TLS ? 'https' : 'http';

let server;
if (TLS) {
  let key, cert;
  try {
    key = readFileSync(process.env.TLS_KEY);
    cert = readFileSync(process.env.TLS_CERT);
  } catch (e) {
    console.error(`\nCan't read the TLS cert/key (${e.path || e.message}). Generate them first:`);
    console.error(`  mkcert -cert-file cert.pem -key-file key.pem <your-ip> localhost   # device-trusted`);
    console.error(`  # or self-signed (simulator only):`);
    console.error(
      `  openssl req -x509 -newkey rsa:2048 -nodes -days 7 -keyout key.pem -out cert.pem -subj "/CN=localhost"`,
    );
    console.error(`Then: TLS_KEY=./key.pem TLS_CERT=./cert.pem PORT=${PORT} npm start\n`);
    process.exit(1);
  }
  server = httpsServer({ key, cert }, handler);
} else {
  server = httpServer(handler);
}

// Bind all interfaces by default so the demo is reachable on your LAN IP, not just
// localhost. Override with HOST=127.0.0.1 to restrict to this machine.
const HOST = process.env.HOST || '0.0.0.0';
server.listen(PORT, HOST, () => {
  console.log(`kunji agent demo listening on ${HOST}:${PORT} (${scheme})`);
  console.log(`  local:  ${scheme}://localhost:${PORT}`);
  console.log(`  LAN:    ${scheme}://<your-ip>:${PORT}  (open from another device on your network)`);
  console.log(`Agent login without a phone:  npm run agent  (then authorize in the wallet)`);
});
