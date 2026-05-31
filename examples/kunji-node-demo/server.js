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
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
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
  console.log(`kunji node demo listening on ${HOST}:${PORT} (${scheme})`);
  console.log(`  local:  ${scheme}://localhost:${PORT}`);
  console.log(`  LAN:    ${scheme}://<your-ip>:${PORT}  (open from another device on your network)`);
  console.log(`Full flow without a phone:  npm run wallet  (add  BASE=${scheme}://<your-ip>:${PORT})`);
});
