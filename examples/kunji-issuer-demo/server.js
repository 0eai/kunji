/**
 * kunji issuer demo — a framework-free, Firebase-free credential ISSUER.
 *
 * Plain Node `http`. Publishes its signing keys, mints SD-JWT VCs on request, and serves a
 * StatusList for revocation. The RP that later verifies a presentation fetches the keys from
 * /.well-known here — kunji is NOT in the path. See ../../docs/verified-credentials.md.
 *
 * Endpoints:
 *   GET  /.well-known/kunji-issuer.json  → { issuer, name, keys:[{kid,kty,crv,x}] }
 *   POST /issue        ← { holderJwk, vct?, claims? } → { credential, idx, issuer }
 *   GET  /status/1?idx= → { valid }   (the RP's checkStatus polls this)
 *   POST /status/revoke ← { idx }     (demo control: revoke a credential)
 *   GET  /*            → a minimal info page
 */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { wellKnown, issue, isValid, revoke, issuerOrigin } from './issuer.js';

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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;

  if (req.method === 'GET' && path === '/.well-known/kunji-issuer.json') return json(res, 200, wellKnown());

  if (req.method === 'POST' && path === '/issue') {
    const body = await readBody(req);
    if (!body?.holderJwk) return json(res, 400, { error: 'holderJwk_required' });
    const { credential, idx } = issue({ holderJwk: body.holderJwk, vct: body.vct, claims: body.claims });
    return json(res, 200, { credential, idx, issuer: issuerOrigin() });
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
  console.log(`  issue:  POST ${issuerOrigin()}/issue   { holderJwk, claims? }`);
  console.log(`  status: GET  ${issuerOrigin()}/status/1?idx=N`);
});
