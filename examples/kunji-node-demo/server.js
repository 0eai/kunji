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
 * OpenID4VP interop (a standalone verifier flow, same SD-JWT VC — docs/oid4vc.md):
 *   GET  /oid4vp/request   → an authorization request (presentation_definition) + state
 *   POST /oid4vp/response  ← direct_post { vp_token, presentation_submission, state }; verified locally
 *   GET  /oid4vp/result?state= → { approved, claims }
 *
 * Swapping the Map for Postgres/Redis and `http` for Express is a 1:1 mapping.
 */
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { verifyAssertion } from './verify.js';
import { verifyCredentialPresentation, parseVcScope } from './vc.js';
import { verifyBbsPresentation, isBbsPresentation, decodeBbsPresentation } from './vcBbs.js';
import { b64uToBytes } from './bbs.js';
import {
  buildPresentationDefinition,
  buildDcqlQuery,
  buildSignedAuthorizationRequest,
  verifyVpToken,
  BBS_VC_FORMAT,
} from './oid4vc.js';

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 2 * 60 * 1000;
// Optional: require a verified credential at login, e.g. REQUIRE_VC="vc:age#age_over_18". When set,
// /api/session advertises it in `scope` and /kunji/callback rejects unless a presentation discloses
// every requested claim as `true`.
const REQUIRE_VC = process.env.REQUIRE_VC || null;
const __dirname = dirname(fileURLToPath(import.meta.url));
// base64url session id / challenge — ~30% shorter than hex (leaner QR), same entropy.
const token = (n) => randomBytes(n).toString('base64url');

// In-memory store. A real RP uses its own DB; the shape is the same.
const sessions = new Map(); // sessionId → { challenge, audience, callbackUrl, status, sub, claims, expiresAt }
const vpRequests = new Map(); // state → { nonce, clientId, presentationDefinition, approved, claims, expiresAt } (OpenID4VP)
const sweep = () => {
  const now = Date.now();
  for (const [id, s] of sessions) if (now > s.expiresAt + 5 * 60_000) sessions.delete(id);
  for (const [id, r] of vpRequests) if (now > r.expiresAt + 5 * 60_000) vpRequests.delete(id);
};

// The single credential this verifier asks for over OpenID4VP (an age proof). Reuses the same
// SD-JWT VC + KB-JWT as the login path — only the request/response envelope differs.
const VP_QUERY = { vct: 'age', disclose: ['age_over_18'] };

// The verifier's request-signing key — published at /.well-known/kunji-verifier.json so a wallet can
// verify a signed authorization request (the HTTPS-anchored client_id scheme; mirrors the issuer key).
// Persisted to .verifier-key (git-ignored), like the issuer demo's .issuer-key. See docs/oid4vc.md.
const VKEYFILE = new URL('./.verifier-key', import.meta.url);
const VERIFIER_KID = 'verifier-key-1';
const loadVerifierKey = () => {
  let sk;
  if (existsSync(VKEYFILE)) {
    sk = new Uint8Array(Buffer.from(readFileSync(VKEYFILE, 'utf8').trim(), 'base64'));
  } else {
    ({ secretKey: sk } = ed25519.keygen());
    writeFileSync(VKEYFILE, Buffer.from(sk).toString('base64'));
  }
  return { secretKey: sk, publicKey: ed25519.getPublicKey(sk) };
};
const verifierWellKnown = (clientId) => ({
  client_id: clientId,
  name: 'kunji node demo (verifier)',
  keys: [{ kid: VERIFIER_KID, kty: 'OKP', crv: 'Ed25519', x: Buffer.from(loadVerifierKey().publicKey).toString('base64url') }],
});

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

// Verified-credentials trust anchors (used only if an assertion presents a credential). The issuer's
// signing keys come from ITS OWN /.well-known — kunji is not in the path. A real RP caches + pins
// these and guards the fetch against SSRF; this demo keeps it simple.
const fetchIssuerKeys = async (iss) => {
  const resp = await fetch(`${iss}/.well-known/kunji-issuer.json`);
  if (!resp.ok) throw new Error('issuer_unreachable');
  return (await resp.json()).keys || [];
};
const fetchStatus = async (uri, idx) => {
  const resp = await fetch(`${uri}?idx=${encodeURIComponent(idx)}`);
  if (!resp.ok) throw new Error('status_unreachable');
  return (await resp.json()).valid !== false; // false ⇒ revoked
};
// Resolve the issuer's BBS public key (the `alg:'BBS'` entry) from its /.well-known — for v3 (BBS)
// unlinkable presentations. Same trust anchor as fetchIssuerKeys; kunji is not in the path.
const fetchIssuerBbsKey = async (iss) => {
  const keys = await fetchIssuerKeys(iss);
  const k = keys.find((x) => x.alg === 'BBS' && x.pub);
  if (!k) throw new Error('issuer_bbs_key_not_found');
  return b64uToBytes(k.pub);
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
    const sessionId = token(16);
    const challenge = token(32);
    const expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(sessionId, {
      challenge,
      audience,
      callbackUrl,
      status: 'pending',
      sub: null,
      claims: null,
      verified: null,
      expiresAt,
    });
    const scope = REQUIRE_VC ? ['login', REQUIRE_VC] : ['login'];
    return json(res, 200, { sessionId, challenge, audience, callbackUrl, expiresAt, scope });
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
    // Optional: verified credentials presented inside the (signed) assertion. Verified LOCALLY
    // against each issuer's own keys + StatusList — no kunji server. Any invalid/revoked one rejects
    // the whole login. The KB-JWT's nonce is this session's challenge, so a presentation can't be
    // replayed to another session.
    let verified = null;
    const presentations = assertion?.signedPayload?.vc_presentations;
    if (Array.isArray(presentations) && presentations.length) {
      verified = [];
      for (const presentation of presentations) {
        // Dispatch by format: a `bbs~`-tagged entry is an unlinkable BBS proof (v3); else SD-JWT.
        const vr = isBbsPresentation(presentation)
          ? await verifyBbsPresentation({
              presentation: decodeBbsPresentation(presentation),
              getIssuerBbsKey: fetchIssuerBbsKey,
              audience: session.audience,
              nonce: session.challenge,
            })
          : await verifyCredentialPresentation({
              presentation,
              audience: session.audience,
              nonce: session.challenge,
              getIssuerKeys: fetchIssuerKeys,
              checkStatus: fetchStatus,
            });
        if (!vr.ok) return json(res, 400, { error: 'vc_' + vr.error });
        verified.push({ iss: vr.iss, vct: vr.vct, claims: vr.claims });
      }
    }
    // Enforce a required credential/predicate: a verified presentation must match the required vct
    // (+ issuer if pinned) and disclose every requested claim as `true` (e.g. age_over_18).
    if (REQUIRE_VC) {
      const want = parseVcScope(REQUIRE_VC);
      const ok = (verified || []).some(
        (v) =>
          v.vct === want.vct &&
          (!want.iss || v.iss === want.iss) &&
          want.disclose.every((c) => v.claims?.[c] === true),
      );
      if (!ok) return json(res, 400, { error: 'vc_predicate_failed' });
    }
    session.status = 'approved';
    session.sub = r.sub;
    session.claims = r.claims;
    session.verified = verified;
    return json(res, 200, { status: 'ok' });
  }

  // 3. The widget/frontend polls this until approved.
  if (req.method === 'GET' && path === '/kunji/status') {
    const s = sessions.get(url.searchParams.get('sessionId') || '');
    if (!s) return json(res, 404, { error: 'unknown_session' });
    return json(res, 200, { status: s.status, sub: s.sub, claims: s.claims, verified: s.verified });
  }

  // ── OpenID4VP (presentation) — a STANDALONE verifier flow (distinct from the kunji login above).
  // Verified locally with the SAME verifyCredentialPresentation; the wallet talks to us directly, no
  // kunji server. See docs/oid4vc.md. ──────────────────────────────────────────────────────────────
  //
  // 3z. The verifier's signing key (HTTPS-anchored client_id scheme) — the wallet fetches this to
  // verify a signed authorization request, proving this verifier controls its origin.
  if (req.method === 'GET' && path === '/.well-known/kunji-verifier.json') {
    const base = originOf(req).callbackUrl.replace(/\/kunji\/callback$/, '');
    return json(res, 200, verifierWellKnown(base));
  }

  // 3a. Build an authorization request (direct_post) for an age VC. Defaults to a SIGNED request (JAR)
  // carrying a DCQL query; `?signed=0` emits the unsigned query-param form and `?query=pd` uses a
  // presentation_definition instead of DCQL (so both interop paths stay exercisable).
  if (req.method === 'GET' && path === '/oid4vp/request') {
    sweep();
    const { callbackUrl } = originOf(req);
    const base = callbackUrl.replace(/\/kunji\/callback$/, '');
    const state = token(16);
    const nonce = token(24);
    const clientId = base; // the verifier's origin (HTTPS-anchored client_id) — also the KB-JWT `aud`
    const wantBbs = url.searchParams.get('format') === 'bbs'; // request an unlinkable (v3) credential
    const usePd = !wantBbs && url.searchParams.get('query') === 'pd'; // BBS uses DCQL
    const signed = url.searchParams.get('signed') !== '0';
    const presentationDefinition = usePd ? buildPresentationDefinition(VP_QUERY) : undefined;
    const dcqlQuery = usePd
      ? undefined
      : buildDcqlQuery({ id: 'age_cred', ...VP_QUERY, ...(wantBbs ? { format: BBS_VC_FORMAT } : {}) });
    vpRequests.set(state, {
      nonce,
      clientId,
      presentationDefinition,
      dcqlQuery,
      approved: null,
      claims: null,
      expiresAt: Date.now() + SESSION_TTL_MS,
    });
    const params = {
      response_type: 'vp_token',
      client_id: clientId,
      response_mode: 'direct_post',
      response_uri: `${base}/oid4vp/response`,
      nonce,
      state,
      ...(usePd ? { presentation_definition: presentationDefinition } : { dcql_query: dcqlQuery }),
    };
    let requestUri;
    if (signed) {
      const requestJwt = buildSignedAuthorizationRequest(loadVerifierKey().secretKey, { kid: VERIFIER_KID, params });
      requestUri = `openid4vp://?${new URLSearchParams({ client_id: clientId, request: requestJwt }).toString()}`;
    } else {
      const q = { ...params };
      if (q.presentation_definition) q.presentation_definition = JSON.stringify(q.presentation_definition);
      if (q.dcql_query) q.dcql_query = JSON.stringify(q.dcql_query);
      requestUri = `openid4vp://?${new URLSearchParams(q).toString()}`;
    }
    return json(res, 200, { state, requestUri });
  }

  // 3b. direct_post: the wallet posts { vp_token, presentation_submission?, state }. The vp_token is a
  // bare SD-JWT string (presentation_definition) or an object keyed by the DCQL credential id. Verify locally.
  if (req.method === 'POST' && path === '/oid4vp/response') {
    const body = await readBody(req);
    const r = body?.state && vpRequests.get(body.state);
    if (!r) return json(res, 400, { error: 'unknown_state' });
    if (Date.now() > r.expiresAt) return json(res, 400, { error: 'expired' });
    const vr = await verifyVpToken({
      vpToken: body.vp_token,
      presentationDefinition: r.presentationDefinition,
      dcqlQuery: r.dcqlQuery,
      getIssuerKeys: fetchIssuerKeys,
      getIssuerBbsKey: fetchIssuerBbsKey, // dispatches when the vp_token is a `bbs~` BBS proof (v3)
      checkStatus: fetchStatus,
      clientId: r.clientId,
      nonce: r.nonce,
    });
    r.approved = vr.ok;
    r.claims = vr.ok ? vr.claims : null;
    if (!vr.ok) return json(res, 400, { error: 'vp_' + vr.error });
    return json(res, 200, { status: 'approved', iss: vr.iss, vct: vr.vct, claims: vr.claims });
  }

  // 3c. Poll the outcome by state (so a browser/sim that issued the request can read the result).
  if (req.method === 'GET' && path === '/oid4vp/result') {
    const r = vpRequests.get(url.searchParams.get('state') || '');
    if (!r) return json(res, 404, { error: 'unknown_state' });
    return json(res, 200, { approved: r.approved, claims: r.claims });
  }

  // (v3 BBS presentation is now served by the unified /oid4vp/{request,response} above — a
  // `?format=bbs` request → a `vc+bbs` DCQL query → verifyVpToken dispatches on the `bbs~` token.)

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
  console.log(`kunji node demo listening on ${HOST}:${PORT} (${scheme})`);
  console.log(`  local:  ${scheme}://localhost:${PORT}`);
  console.log(`  LAN:    ${scheme}://<your-ip>:${PORT}  (open from another device on your network)`);
  console.log(`Full flow without a phone:  npm run wallet  (add  BASE=${scheme}://<your-ip>:${PORT})`);
  console.log(`OpenID4VC interop demo:     npm run oid4vc  (needs the issuer demo running)`);
});
