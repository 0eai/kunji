/**
 * kunji issuer demo — a framework-free, Firebase-free credential ISSUER.
 *
 * Plain Node `http`. Publishes its signing keys, mints SD-JWT VCs on request, and serves a
 * StatusList for revocation. The RP that later verifies a presentation fetches the keys from
 * /.well-known here — kunji is NOT in the path. See ../../docs/verified-credentials.md.
 *
 * Endpoints:
 *   GET  /.well-known/kunji-issuer.json  → { issuer, name, keys:[{kid,kty,crv,x}] }
 *   POST /issue        ← { holderJwk, vct?, claims? } → { credential, idx, issuer }   (kunji-native)
 *   GET  /status/1?idx= → { valid }   (the RP's checkStatus polls this)
 *   POST /status/revoke ← { idx }     (demo control: revoke a credential)
 *   GET  /*            → a minimal info page
 *
 * OpenID4VCI interop (same SD-JWT VC, standard envelope — docs/oid4vc.md):
 *   GET  /.well-known/openid-credential-issuer    → issuer metadata
 *   GET  /.well-known/oauth-authorization-server  → token endpoint metadata
 *   GET  /credential-offer  → mint a pre-authorized_code → { offer, offerUri }
 *   POST /token             ← pre-authorized_code grant → { access_token, c_nonce, … }
 *   POST /credential        ← Bearer token + holder proof JWT → { credential }
 */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { wellKnown, issue, issueBatch, issueBbs, isValid, revoke, issuerOrigin, MAX_BATCH } from './issuer.js';
import { depositToRelay } from './relay.js';
import {
  credentialIssuerMetadata,
  authServerMetadata,
  createOffer,
  handleAuthorize,
  handleToken,
  handleCredential,
} from './oid4vci.js';

const PORT = process.env.PORT || 4000;
const __dirname = dirname(fileURLToPath(import.meta.url));
const json = (res, code, body) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(body));
};
const readBody = (req) =>
  new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => {
      d += c;
      if (d.length > 256 * 1024) req.destroy();
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(d || '{}'));
      } catch {
        resolve(null);
      }
    });
  });

const server = createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;

  if (req.method === 'GET' && path === '/.well-known/kunji-issuer.json') return json(res, 200, wellKnown());

  if (req.method === 'POST' && path === '/issue') {
    const body = await readBody(req);
    // Unlinkable ask (v3, BBS): one credential, fresh ZK proof per presentation — no holder key needed.
    if (body?.format === 'bbs') {
      const { credential } = await issueBbs({ dob: body.dob, vct: body.vct, claims: body.claims, holderBinding: body.holderBinding });
      return json(res, 200, { credential, issuer: issuerOrigin() });
    }
    // Batch ask (unlinkability v2): one one-time copy per holder key, each its own signature + status idx.
    if (Array.isArray(body?.holderJwks) && body.holderJwks.length) {
      if (body.holderJwks.length > MAX_BATCH) return json(res, 400, { error: 'batch_too_large', max: MAX_BATCH }); // [S24]
      const minted = issueBatch({ holderJwks: body.holderJwks, dob: body.dob, vct: body.vct, claims: body.claims });
      return json(res, 200, { credentials: minted.map((m) => m.credential), issuer: issuerOrigin() });
    }
    if (!body?.holderJwk) return json(res, 400, { error: 'holderJwk_required' });
    const { credential, idx } = issue({ holderJwk: body.holderJwk, dob: body.dob, vct: body.vct, claims: body.claims });
    // Async path: ECDH-encrypt + deposit to the kunji relay for the wallet to poll (out-of-band issuance).
    if (body.deposit && body.transportPub && body.sessionId) {
      try {
        await depositToRelay({ sdjwt: credential, transportPub: body.transportPub, sessionId: body.sessionId, issuer: issuerOrigin() });
        return json(res, 200, { status: 'deposited', idx, issuer: issuerOrigin() });
      } catch {
        return json(res, 502, { error: 'relay_deposit_failed' });
      }
    }
    return json(res, 200, { credential, idx, issuer: issuerOrigin() });
  }

  // ── OpenID4VCI interop (same SD-JWT VC, standard envelope) ──────────────────────────────
  if (req.method === 'GET' && path === '/.well-known/openid-credential-issuer')
    return json(res, 200, credentialIssuerMetadata());
  if (req.method === 'GET' && path === '/.well-known/oauth-authorization-server')
    return json(res, 200, authServerMetadata());
  if (req.method === 'GET' && path === '/credential-offer')
    return json(res, 200, createOffer({ authCode: url.searchParams.get('grant') === 'authorization_code' }));
  if (req.method === 'GET' && path === '/authorize') {
    const r = handleAuthorize(Object.fromEntries(url.searchParams));
    if (r.status === 302) {
      res.writeHead(302, { Location: r.location });
      return res.end();
    }
    return json(res, r.status, r.json);
  }
  if (req.method === 'GET' && path === '/callback') {
    // A trivial holder-return endpoint for poking the demo by hand; the sim follows the 302 itself.
    return json(res, 200, { code: url.searchParams.get('code'), state: url.searchParams.get('state') });
  }
  if (req.method === 'POST' && path === '/token') {
    const r = await handleToken(await readBody(req), { dpop: req.headers.dpop, htu: `${issuerOrigin()}/token` });
    return json(res, r.status, r.json);
  }
  if (req.method === 'POST' && path === '/credential') {
    const r = await handleCredential({
      authorization: req.headers.authorization,
      dpop: req.headers.dpop,
      htu: `${issuerOrigin()}/credential`,
      body: await readBody(req),
    });
    return json(res, r.status, r.json);
  }

  if (req.method === 'GET' && path === '/status/1') {
    return json(res, 200, { valid: isValid(url.searchParams.get('idx')) });
  }
  if (req.method === 'POST' && path === '/status/revoke') {
    const body = await readBody(req);
    if (typeof body?.idx === 'undefined') return json(res, 400, { error: 'idx_required' });
    revoke(body.idx);
    return json(res, 200, { ok: true, revoked: Number(body.idx) });
  }

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

const HOST = process.env.HOST || '0.0.0.0';
server.listen(PORT, HOST, () => {
  console.log(`kunji issuer demo on ${issuerOrigin()}`);
  console.log(`  keys:   ${issuerOrigin()}/.well-known/kunji-issuer.json`);
  console.log(`  issue:  POST ${issuerOrigin()}/issue   { holderJwk, claims? }   (kunji-native)`);
  console.log(`  status: GET  ${issuerOrigin()}/status/1?idx=N`);
  console.log(`  oid4vci: GET ${issuerOrigin()}/.well-known/openid-credential-issuer · GET /credential-offer`);
});
