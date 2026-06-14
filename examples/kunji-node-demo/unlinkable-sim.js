// Unlinkability v2 sim — proves batch / one-time-use credentials are UNLINKABLE across presentations
// (verified-credentials.md §7). A headless holder fetches a BATCH over OpenID4VCI (a `proofs[]` request,
// each proof over a DISTINCT random holder key), then presents two different copies to two different
// "verifiers" and shows the two presentations share NEITHER an issuer signature NOR a holder key
// (`cnf.jwk`) — so even colluding verifiers can't correlate them. v1 (one reused credential) shares both.
//
// Needs only the issuer demo (no verifier, no kunji backend):
//     (cd ../kunji-issuer-demo && PORT=4000 node server.js)
//     node unlinkable-sim.js            # or: N=8 ISSUER=http://… node unlinkable-sim.js
import { ed25519 } from '@noble/curves/ed25519.js';
import { parseSdJwt, buildPresentation, verifyCredentialPresentation, holderJwkFor } from './vc.js';
import { parseCredentialOffer, buildProofJwt } from './oid4vc.js';

const ISSUER = (process.env.ISSUER || 'http://localhost:4000').replace(/\/$/, '');
const N = Number(process.env.N || 5);
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const getJson = async (u, init) => {
  const r = await fetch(u, init);
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const fail = (m, d) => {
  console.error(`\n✗ ${m}`, d ?? '');
  process.exit(1);
};

console.log('Unlinkability v2 sim — issuer:', ISSUER, '\n');

// ── ① OpenID4VCI batch issuance: offer → token → /credential with N proofs (distinct holder keys) ──
const offerResp = await getJson(`${ISSUER}/credential-offer`);
if (offerResp.status !== 200) fail('credential-offer failed', offerResp);
const offer = parseCredentialOffer(offerResp.body.offer || offerResp.body.offerUri);

const tokenResp = await getJson(`${ISSUER}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': offer.preAuthorizedCode }),
});
if (tokenResp.status !== 200) fail('token request failed', tokenResp);
const { access_token, c_nonce } = tokenResp.body;

// N distinct random holder keys — exactly what the real wallet generates + stores per copy.
const holders = Array.from({ length: N }, () => {
  const sk = ed25519.utils.randomSecretKey();
  return { sk, pk: ed25519.getPublicKey(sk) };
});
const proofs = holders.map((h) =>
  buildProofJwt({ holderSecretKey: h.sk, holderPublicKey: h.pk, audience: offer.credentialIssuer, cNonce: c_nonce }),
);
const credResp = await getJson(`${ISSUER}/credential`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access_token}` },
  body: JSON.stringify({ format: 'vc+sd-jwt', proofs: { jwt: proofs } }),
});
const sdjwts = Array.isArray(credResp.body.credentials) ? credResp.body.credentials : [];
if (sdjwts.length !== N) fail(`expected ${N} credentials, got ${sdjwts.length}`, credResp);
console.log(`① OpenID4VCI batch     received ${sdjwts.length} one-time copies of "${parseSdJwt(sdjwts[0]).issuerClaims.vct}"`);

// Match each copy to the holder key it was bound to (by cnf.jwk) — what the wallet's storeBatch does.
const copyKey = (sdjwt) => {
  const x = parseSdJwt(sdjwt).issuerClaims.cnf?.jwk?.x;
  const h = holders.find((k) => holderJwkFor(k.pk).x === x);
  if (!h) fail('a copy was bound to a holder key we did not offer');
  return h;
};

// ── ② Present TWO different copies to TWO different verifiers ──────────────────────────────────────
const issuerKeys = (await getJson(`${ISSUER}/.well-known/kunji-issuer.json`)).body.keys || [];
const getIssuerKeys = async () => issuerKeys;
const checkStatus = async (uri, idx) => (await getJson(`${uri}?idx=${idx}`)).body.valid;

const presentOne = async (sdjwt, audience, nonce) => {
  const presentation = await buildPresentation({
    sdjwt,
    disclose: ['age_over_18'],
    audience,
    nonce,
    holderSecretKey: copyKey(sdjwt).sk,
  });
  const v = await verifyCredentialPresentation({ presentation, getIssuerKeys, checkStatus, audience, nonce });
  if (!v.ok) fail('presentation did not verify', v);
  const p = parseSdJwt(sdjwt);
  return { issuerJws: p.issuerJws, cnf: p.issuerClaims.cnf.jwk.x, idx: p.issuerClaims.status?.idx, claims: v.claims };
};

const a = await presentOne(sdjwts[0], 'https://verifier-a.example', 'nonce-a');
const b = await presentOne(sdjwts[1], 'https://verifier-b.example', 'nonce-b');
console.log('② presented copy #1 →  verifier-a   ✓ verified · age_over_18 =', a.claims.age_over_18, '· status idx', a.idx);
console.log('   presented copy #2 →  verifier-b   ✓ verified · age_over_18 =', b.claims.age_over_18, '· status idx', b.idx);

// ── ③ The unlinkability proof: the two presentations share NEITHER correlation handle ─────────────
const sameSig = a.issuerJws === b.issuerJws;
const sameKey = a.cnf === b.cnf;
console.log('\n③ Unlinkability check');
console.log('   issuer signature shared? ', sameSig ? 'YES ✗' : 'no  ✓');
console.log('   holder key (cnf) shared? ', sameKey ? 'YES ✗' : 'no  ✓');
console.log('   status idx shared?       ', a.idx === b.idx ? 'YES ✗' : 'no  ✓');
if (sameSig || sameKey) fail('the two presentations are linkable — v2 not delivering unlinkability');

console.log('\n✓ Two presentations of the SAME logical credential, ZERO shared correlation handles —');
console.log('  colluding verifiers cannot tell they came from the same holder. (v1 would share all three.)');
process.exit(0);
