/**
 * Wallet simulator — runs the full discoverable-login flow against the demo server
 * WITHOUT a phone or a public URL. It does what the real kunji wallet does on the
 * signing side: derive a per-app Ed25519 key, build the §5.2 assertion, sign it over
 * canonical JSON, and POST it to the RP's callback. Then it polls for approval.
 *
 *   node wallet-sim.js              # default identity only
 *   node wallet-sim.js --claims     # also share a (fake) self-asserted profile
 *   BASE=https://your-tunnel.example node wallet-sim.js
 *
 * (The real wallet derives the keypair deterministically from the user's master key +
 * audience; here we just generate a random one — the RP can't tell the difference.)
 */
import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { canonicalJson } from './verify.js';
import { buildPresentation, holderJwkFor, parseVcScope } from './vc.js';
// Reuse kunji's shared default-identity helper for a friendly printout. A real RP would
// use window.kunji.handle(sub) from rp.js (see public/index.html).
import { deriveHandle } from '../../src/lib/kunjiHandle.js';
import { buildBbsVpToken } from './oid4vc.js';
import { b64uToBytes, bytesToB64u } from './bbs.js';

const BASE = process.env.BASE || 'http://localhost:3000';
const wantClaims = process.argv.includes('--claims');
// --vc: also act as a credential HOLDER — fetch a VC from the issuer and present it. --revoke first
// revokes it at the issuer (the RP should then reject the presentation).
const wantVc = process.argv.includes('--vc');
// --bbs: present an UNLINKABLE (BBS, v3) age credential at login instead of an SD-JWT one.
const wantBbs = process.argv.includes('--bbs');
const wantRevoke = process.argv.includes('--revoke');
const ISSUER = process.env.ISSUER;

// This is a local testing tool, so accept self-signed / mkcert HTTPS certs when BASE is
// https (Node's fetch verifies TLS by default). A REAL browser wallet does NOT do this —
// it requires a device-trusted cert. Never copy this into production code.
if (BASE.startsWith('https:')) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const b64 = (u8) => Buffer.from(u8).toString('base64');

const main = async () => {
  // 1. Ask the RP for a session (what the QR/widget does first).
  const session = await (
    await fetch(`${BASE}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
  ).json();
  console.log('session:', session.sessionId, '· audience:', session.audience);

  // 2. Derive the per-app identity (random keypair stands in for the master-key derivation).
  const priv = ed25519.utils.randomSecretKey();
  const publicKeyB64 = b64(ed25519.getPublicKey(priv));
  const sub = createHash('sha256').update(publicKeyB64, 'utf8').digest('hex');

  // 3. Build + sign the assertion (spec §5.2).
  const signedPayload = {
    sessionId: session.sessionId,
    challenge: session.challenge,
    audience: session.audience,
    sub,
    timestamp: Date.now(),
  };
  if (wantClaims) {
    // A real wallet would only attach this on explicit user consent.
    signedPayload.claims = { name: 'Ada Lovelace', picture: 'data:image/svg+xml,<svg/>' };
  }

  // --vc: act as a credential HOLDER — get an SD-JWT VC from the issuer, then PRESENT it
  // (selective disclosure of `age_over_18` + a Key-Binding JWT bound to this session's challenge)
  // inside the signed assertion. Corresponds to an RP requesting scope:["login","vc:age_over_18"].
  // The holder key is random here; the real wallet derives it per-issuer (deriveCredentialHolderKey).
  if (wantVc) {
    if (!ISSUER) throw new Error('Set ISSUER=<issuer origin>, e.g. ISSUER=http://localhost:4000');
    // Fulfill the vc: scopes the RP advertised (session.scope), or default to age_over_18 so `--vc`
    // alone still demos. VC_DOB sets the holder's age at the issuer (e.g. a minor → an 18+ rejection).
    let vcReqs = (session.scope || [])
      .map((s) => (typeof s === 'string' ? s : s.id))
      .map(parseVcScope)
      .filter(Boolean);
    if (!vcReqs.length) vcReqs = [{ vct: 'age', iss: undefined, disclose: ['age_over_18'] }];

    const holderPriv = ed25519.utils.randomSecretKey();
    const holderPub = ed25519.getPublicKey(holderPriv);
    const dob = process.env.VC_DOB; // e.g. VC_DOB=2010-01-01 (a minor) — issuer defaults to an adult
    const presentations = [];
    for (const req of vcReqs) {
      const issued = await (
        await fetch(`${ISSUER}/issue`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ holderJwk: holderJwkFor(holderPub), dob }),
        })
      ).json();
      if (!issued.credential) throw new Error('issuer /issue failed: ' + JSON.stringify(issued));
      if (wantRevoke) {
        await fetch(`${ISSUER}/status/revoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idx: issued.idx }),
        });
        console.log(`(revoked credential idx ${issued.idx} at the issuer — presentation should be rejected)`);
      }
      presentations.push(
        buildPresentation({
          sdjwt: issued.credential,
          disclose: req.disclose,
          audience: session.audience,
          nonce: session.challenge,
          holderSecretKey: holderPriv,
        }),
      );
      console.log(`presenting ${req.vct} disclosing [${req.disclose.join(', ')}] from`, issued.issuer);
    }
    signedPayload.vc_presentations = presentations;
  }

  // --bbs: present an UNLINKABLE (v3) age credential at login — one BBS credential → a fresh randomized
  // proof bound to this session, carried as a tagged string in vc_presentations (the RP dispatches on it).
  if (wantBbs) {
    if (!ISSUER) throw new Error('Set ISSUER=<issuer origin>, e.g. ISSUER=http://localhost:4000');
    // The real wallet derives the holder secret from its master key (deriveBbsHolderSecret); the sim
    // uses a random value, sent at issuance + reused to present (non-transferability).
    const holderSecret = crypto.getRandomValues(new Uint8Array(32));
    const issued = await (
      await fetch(`${ISSUER}/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: 'bbs', holderBinding: bytesToB64u(holderSecret) }),
      })
    ).json();
    if (issued.credential?.format !== 'bbs') throw new Error('issuer BBS /issue failed: ' + JSON.stringify(issued));
    const wk = await (await fetch(`${ISSUER}/.well-known/kunji-issuer.json`)).json();
    const bbsKey = (wk.keys || []).find((k) => k.alg === 'BBS');
    if (!bbsKey) throw new Error('issuer published no BBS key');
    const token = await buildBbsVpToken({
      credential: issued.credential,
      disclose: ['age_over_18'],
      clientId: session.audience,
      nonce: session.challenge,
      issuerPublicKey: b64uToBytes(bbsKey.pub),
      holderSecret,
    });
    signedPayload.vc_presentations = [token];
    console.log('presenting an UNLINKABLE (BBS) age credential disclosing [age_over_18] from', issued.issuer);
  }

  const signedToken = b64(
    ed25519.sign(new TextEncoder().encode(canonicalJson(signedPayload)), priv),
  );

  // 4. POST it straight to the RP's callback (no kunji server involved).
  const cb = await fetch(session.callbackUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: publicKeyB64, signedPayload, signedToken }),
  });
  console.log('callback:', cb.status, await cb.json().catch(() => ({})));

  // 5. Poll status, like the RP frontend.
  const status = await (
    await fetch(`${BASE}/kunji/status?sessionId=${session.sessionId}`)
  ).json();

  const handle = deriveHandle(sub);
  console.log('\nResult:');
  console.log('  status :', status.status);
  console.log('  sub    :', status.sub);
  console.log('  default:', handle.name, '(+ identicon)');
  console.log('  claims :', status.claims || '(none — RP uses the default identity)');
  if (wantVc) console.log('  verified:', status.verified ? JSON.stringify(status.verified) : '(none — presentation was rejected; see callback above)');
};

main().catch((e) => {
  console.error('wallet-sim failed:', e.message);
  console.error('Is the server running?  npm start');
  process.exit(1);
});
