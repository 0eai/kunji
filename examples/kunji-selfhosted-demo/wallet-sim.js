/**
 * Wallet simulator — exercises the deployed self-hosted RP with no phone.
 * It does the wallet's signing side and POSTs to your PUBLIC Firebase endpoints, then
 * checks that a Firebase **custom token** came back (proving the §7 bridge works).
 *
 *   BASE=https://app.yourdomain.com node wallet-sim.js          # default identity
 *   BASE=https://your-proj.web.app  node wallet-sim.js --claims # share a (fake) profile
 *
 * (Browser-only step not covered here: signInWithCustomToken — see public/index.html.)
 */
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { ed25519 } from '@noble/curves/ed25519.js';
import { canonicalJson } from './functions/verify.js';

const BASE = process.env.BASE;
const wantClaims = process.argv.includes('--claims');
const b64 = (u8) => Buffer.from(u8).toString('base64');

if (!BASE) {
  console.error('Set BASE to your deployed Hosting URL, e.g. BASE=https://your-proj.web.app');
  process.exit(1);
}

const main = async () => {
  // 1. Create a session (the browser does this via the widget).
  const session = await (
    await fetch(`${BASE}/api/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
  ).json();
  console.log('session:', session.sessionId, '· audience:', session.audience);

  // 2. Derive a per-app key and sign the assertion (spec §5.2).
  const priv = ed25519.utils.randomSecretKey();
  const publicKeyB64 = b64(ed25519.getPublicKey(priv));
  const sub = createHash('sha256').update(publicKeyB64, 'utf8').digest('hex');
  const signedPayload = {
    sessionId: session.sessionId,
    challenge: session.challenge,
    audience: session.audience, // server-authoritative (your Hosting/custom domain)
    sub,
    timestamp: Date.now(),
  };
  if (wantClaims) signedPayload.claims = { name: 'Ada Lovelace', picture: 'data:image/svg+xml,<svg/>' };
  const signedToken = b64(ed25519.sign(new TextEncoder().encode(canonicalJson(signedPayload)), priv));

  // 3. POST to the public callback (what a phone on any network does).
  const cb = await fetch(`${BASE}/kunji/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: publicKeyB64, signedPayload, signedToken }),
  });
  console.log('callback:', cb.status, await cb.json().catch(() => ({})));

  // 4. Poll status — once approved a Firebase custom token is guaranteed present.
  let s = {};
  for (let i = 0; i < 15; i++) {
    s = await (await fetch(`${BASE}/kunji/status?sessionId=${session.sessionId}`)).json();
    if (s.status === 'approved') break;
    await sleep(400);
  }
  console.log('\nstatus :', s.status);
  console.log('  sub        :', s.sub);
  console.log('  claims     :', s.claims || '(none — RP uses the default identity)');
  console.log('  customToken:', s.customToken ? '✔ minted (browser would signInWithCustomToken)' : '✗ missing');
};

main().catch((e) => {
  console.error('wallet-sim failed:', e.message);
  console.error('Deployed functions + Hosting reachable at BASE?');
  process.exit(1);
});
