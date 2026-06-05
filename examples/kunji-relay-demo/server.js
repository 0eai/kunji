/**
 * Local RP server — runs on your dev box (dynamic IP, behind NAT), NO tunnel.
 *
 * It never receives an inbound request from the wallet. Instead it talks to Firebase
 * OUTBOUND only: it creates a session (writes Firestore via the Admin SDK), serves the
 * QR frontend, and LISTENS (onSnapshot) for the kunjiCallback Function to write the
 * verified result. Because every connection is outbound, your IP is never needed — so
 * dynamic IP / NAT / no-tunnel all just work.
 *
 * Setup (see README): deploy functions/ to your Firebase project, then run with:
 *   RELAY_CALLBACK_URL=<deployed kunjiCallback URL> \
 *   GOOGLE_APPLICATION_CREDENTIALS=./serviceAccount.json \
 *   npm start
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { initializeApp, applicationDefault } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

const PORT = process.env.PORT || 3000;
const CALLBACK_URL = process.env.RELAY_CALLBACK_URL;
// The wallet signs `audience` and the Function verifies it; it MUST be the callback's
// host (the wallet requires callbackUrl same-site as audience).
const AUDIENCE = process.env.RELAY_AUDIENCE || (CALLBACK_URL && new URL(CALLBACK_URL).hostname);

if (!CALLBACK_URL || !AUDIENCE) {
  console.error('\nSet RELAY_CALLBACK_URL to your deployed kunjiCallback URL, e.g.');
  console.error('  RELAY_CALLBACK_URL=https://kunjicallback-xxxx-uc.a.run.app \\');
  console.error('  GOOGLE_APPLICATION_CREDENTIALS=./serviceAccount.json npm start\n');
  process.exit(1);
}

initializeApp({ credential: applicationDefault() });
const db = getFirestore();
const __dirname = dirname(fileURLToPath(import.meta.url));
const SESSION_TTL_MS = 2 * 60 * 1000;
// base64url session id / challenge — ~30% shorter than hex (leaner QR), same entropy.
const token = (n) => randomBytes(n).toString('base64url');

// Sessions we created, each with a live Firestore listener. /kunji/status reads this
// cache (no per-poll Firestore reads), and we tear the listener down once resolved.
const local = new Map(); // sessionId → { status, sub, claims, unsub }
const detach = (id) => {
  const e = local.get(id);
  if (e?.unsub) {
    e.unsub();
    e.unsub = null;
  }
};

const startSession = async () => {
  const sessionId = token(16);
  const challenge = token(32);
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const ref = db.collection('relaySessions').doc(sessionId);
  await ref.set({
    challenge,
    audience: AUDIENCE,
    status: 'pending',
    sub: null,
    claims: null,
    expiresAt,
    ttl: new Date(expiresAt + 5 * 60 * 1000), // add a Firestore TTL policy on `ttl` to auto-clean
  });

  const entry = { status: 'pending', sub: null, claims: null, unsub: null };
  entry.unsub = ref.onSnapshot(
    (snap) => {
      const d = snap.data();
      if (!d) return;
      entry.status = d.status;
      entry.sub = d.sub || null;
      entry.claims = d.claims || null;
      if (d.status === 'approved') {
        // ——— your LOCAL business logic runs here, on your dev box ———
        // e.g. upsert your user keyed by d.sub, mint your own app session, etc.
        const who = d.claims?.name ? ` (${d.claims.name})` : '';
        console.log(`✔ ${sessionId} approved · sub=${d.sub}${who}`);
        detach(sessionId);
      }
    },
    (err) => console.error('listener error:', err.message),
  );
  local.set(sessionId, entry);
  setTimeout(() => detach(sessionId), SESSION_TTL_MS + 10_000); // safety cleanup
  return { sessionId, challenge, expiresAt };
};

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

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;

  // The frontend asks where to send the wallet (the public callback) and what audience.
  if (req.method === 'GET' && path === '/config') {
    return json(res, 200, { callbackUrl: CALLBACK_URL, audience: AUDIENCE });
  }
  if (req.method === 'POST' && path === '/api/session') {
    try {
      return json(res, 200, await startSession());
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }
  if (req.method === 'GET' && path === '/kunji/status') {
    const e = local.get(url.searchParams.get('sessionId') || '');
    if (!e) return json(res, 404, { error: 'unknown_session' });
    return json(res, 200, { status: e.status, sub: e.sub, claims: e.claims });
  }
  if (req.method === 'GET' && path === '/app.js') {
    try {
      const js = readFileSync(join(__dirname, 'public', 'app.js'));
      res.writeHead(200, {
        'Content-Type': 'text/javascript; charset=utf-8',
        ...SECURITY_HEADERS,
      });
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
});

server.listen(PORT, () => {
  console.log(`relay demo (local RP) → http://localhost:${PORT}`);
  console.log(`  callback (public Function): ${CALLBACK_URL}`);
  console.log(`  audience: ${AUDIENCE}`);
  console.log(`Test the whole relay without a phone:  npm run wallet`);
});
