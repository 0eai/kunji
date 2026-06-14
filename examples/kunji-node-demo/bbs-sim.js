// Unlinkability v3 sim (BBS over OpenID4VP) — proves single-credential unlinkability through the SAME
// OID4VP envelope the SD-JWT credential uses. A headless holder fetches ONE BBS credential, then answers
// two `vc+bbs` OID4VP requests (two nonces): each is a fresh, randomized zero-knowledge proof revealing
// only the asked claim, bound to (client_id, nonce). The two proofs share no bytes/handle yet both are
// approved by the verifier's /oid4vp/response — from a SINGLE credential (v2 needed N copies). See §7 v3.
//
// Needs the issuer + this RP/verifier:
//     (cd ../kunji-issuer-demo && PORT=4000 node server.js)   # the issuer (BBS key in /.well-known)
//     node server.js                                          # this RP/verifier (port 3000)
//     node bbs-sim.js                                         # the holder
// Override hosts: ISSUER=http://… BASE=http://… node bbs-sim.js
import { buildBbsVpToken, parseAuthorizationRequest, requestQuery, buildVpResponse } from './oid4vc.js';
import { b64uToBytes } from './bbs.js';

const ISSUER = (process.env.ISSUER || 'http://localhost:4000').replace(/\/$/, '');
const BASE = (process.env.BASE || 'http://localhost:3000').replace(/\/$/, '');

const getJson = async (u, init) => {
  const r = await fetch(u, init);
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const fail = (m, d) => {
  console.error(`\n✗ ${m}`, d ?? '');
  process.exit(1);
};

console.log('Unlinkability v3 sim (BBS over OID4VP) — issuer:', ISSUER, '· verifier:', BASE, '\n');

// ── ① Receive ONE unlinkable (BBS) credential ─────────────────────────────────────────────────────
const issued = await getJson(`${ISSUER}/issue`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ format: 'bbs' }),
});
if (issued.status !== 200 || issued.body.credential?.format !== 'bbs') fail('BBS issuance failed', issued);
const credential = issued.body.credential;
console.log(`① received ONE BBS credential   vct = ${credential.vct} · claims:`, credential.names.join(', '));

// The holder derives proofs against the issuer's published BBS key (kunji not in the path).
const wk = await getJson(`${ISSUER}/.well-known/kunji-issuer.json`);
const bbsKey = (wk.body.keys || []).find((k) => k.alg === 'BBS');
if (!bbsKey) fail('issuer published no BBS key', wk);
const issuerPublicKey = b64uToBytes(bbsKey.pub);

// ── ② Answer TWO `vc+bbs` OpenID4VP requests with the SAME credential ──────────────────────────────
const presentOnce = async () => {
  const reqr = await getJson(`${BASE}/oid4vp/request?format=bbs`);
  if (reqr.status !== 200) fail('oid4vp/request failed', reqr);
  const ar = parseAuthorizationRequest(reqr.body.requestUri);
  const q = requestQuery(ar);
  if (q.format !== 'vc+bbs') fail('verifier did not request vc+bbs', q);
  const token = await buildBbsVpToken({
    credential,
    disclose: q.disclose,
    clientId: ar.clientId,
    nonce: ar.nonce,
    issuerPublicKey,
  });
  const resp = await getJson(ar.responseUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(buildVpResponse({ request: ar, presentation: token })),
  });
  return { token, resp };
};

const a = await presentOnce();
const b = await presentOnce();
if (a.resp.status !== 200 || a.resp.body.status !== 'approved') fail('first presentation rejected', a.resp);
if (b.resp.status !== 200 || b.resp.body.status !== 'approved') fail('second presentation rejected', b.resp);
console.log('② presented #1 → /oid4vp/response   ✓ approved · claims =', JSON.stringify(a.resp.body.claims));
console.log('   presented #2 → /oid4vp/response   ✓ approved · claims =', JSON.stringify(b.resp.body.claims));

// ── ③ The v3 proof: two presentations of ONE credential share no handle ────────────────────────────
console.log('\n③ Unlinkability check (ONE credential, two OID4VP presentations)');
console.log('   vp_token bytes shared?   ', a.token === b.token ? 'YES ✗' : 'no  ✓');
if (a.token === b.token) fail('the two proofs are identical — not unlinkable');
console.log('\n✓ One BBS credential, two unlinkable zero-knowledge proofs over standard OpenID4VP —');
console.log('  no signature, no holder key, nothing a colluding verifier can correlate. (v2 needed N copies.)');
process.exit(0);
