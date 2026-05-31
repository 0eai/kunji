/**
 * "Sign in with kunji" — a framework-free, Firebase-free relying party.
 *
 * Plain Node `http` + an in-memory session Map + the §6 verifier in verify.js.
 * This is the whole backend kunji needs: there is NO kunji server in the loop — the
 * wallet POSTs a signed assertion straight to /kunji/callback, and we verify it.
 *
 * Endpoints (same shape the drop-in widget rp.js expects):
 *   POST /api/session   → { sessionId, challenge, audience, callbackUrl, expiresAt }
 *   POST /kunji/callback ← the wallet's signed assertion; runs §6 verification
 *   GET  /kunji/status?sessionId= → { status, sub, claims }
 *   GET  /*             → the static frontend (public/index.html)
 *
 * Swapping the Map for Postgres/Redis and `http` for Express is a 1:1 mapping.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyAssertion } from './verify.js';

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 2 * 60 * 1000;
const __dirname = dirname(fileURLToPath(import.meta.url));
const hex = (n) => randomBytes(n).toString('hex');

// In-memory store. A real RP uses its own DB; the shape is the same.
const sessions = new Map(); // sessionId → { challenge, audience, callbackUrl, status, sub, claims, expiresAt }
const sweep = () => {
  const now = Date.now();
  for (const [id, s] of sessions) if (now > s.expiresAt + 5 * 60_000) sessions.delete(id);
};

const json = (res, code, body) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
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
// (never trust client-supplied values, spec §11). Behind a proxy/tunnel, honor x-forwarded-*.
const originOf = (req) => {
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  const proto = req.headers['x-forwarded-proto'] || (host.startsWith('localhost') ? 'http' : 'https');
  return { audience: host.split(':')[0], callbackUrl: `${proto}://${host}/kunji/callback` };
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;

  // 1. Create a session (the widget calls this first).
  if (req.method === 'POST' && path === '/api/session') {
    sweep();
    const { audience, callbackUrl } = originOf(req);
    const sessionId = hex(16);
    const challenge = hex(32);
    const expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(sessionId, {
      challenge,
      audience,
      callbackUrl,
      status: 'pending',
      sub: null,
      claims: null,
      expiresAt,
    });
    return json(res, 200, { sessionId, challenge, audience, callbackUrl, expiresAt });
  }

  // 2. The wallet POSTs the signed assertion here. Verify + consume atomically.
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

  // 3. The widget/frontend polls this until approved.
  if (req.method === 'GET' && path === '/kunji/status') {
    const s = sessions.get(url.searchParams.get('sessionId') || '');
    if (!s) return json(res, 404, { error: 'unknown_session' });
    return json(res, 200, { status: s.status, sub: s.sub, claims: s.claims });
  }

  // 4. Static frontend.
  if (req.method === 'GET') {
    try {
      const html = readFileSync(join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch {
      return json(res, 500, { error: 'no_frontend' });
    }
  }

  json(res, 405, { error: 'method_not_allowed' });
});

server.listen(PORT, () => {
  console.log(`kunji node demo → http://localhost:${PORT}`);
  console.log(`Test the full flow with no phone:  npm run wallet`);
});
