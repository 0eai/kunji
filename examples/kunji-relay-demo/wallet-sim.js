/**
 * Wallet simulator for the relay demo — exercises the WHOLE path with no phone:
 * local /config + /api/session  →  sign  →  POST to the PUBLIC callback Function  →
 * poll the LOCAL /kunji/status (which is fed by the local server's Firestore listener).
 *
 *   node wallet-sim.js            # default identity
 *   node wallet-sim.js --claims   # also share a (fake) self-asserted profile
 *   BASE=http://localhost:3000 node wallet-sim.js
 *
 * Requires the kunjiCallback Function deployed and `npm start` running locally.
 */
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { ed25519 } from '@noble/curves/ed25519.js';
import { canonicalJson } from './functions/verify.js';

const LOCAL = process.env.BASE || 'http://localhost:3000';
const wantClaims = process.argv.includes('--claims');
const b64 = (u8) => Buffer.from(u8).toString('base64');

const main = async () => {
  // 1. Where does the wallet POST? (the public Function) and what audience to sign.
  const cfg = await (await fetch(`${LOCAL}/config`)).json();
  console.log('callback (public Function):', cfg.callbackUrl);

  // 2. The local RP creates the session (and starts listening to Firestore).
  const session = await (
    await fetch(`${LOCAL}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
  ).json();

  // 3. Derive a per-app key and sign the assertion (spec §5.2).
  const priv = ed25519.utils.randomSecretKey();
  const publicKeyB64 = b64(ed25519.getPublicKey(priv));
  const sub = createHash('sha256').update(publicKeyB64, 'utf8').digest('hex');
  const signedPayload = {
    sessionId: session.sessionId,
    challenge: session.challenge,
    audience: cfg.audience,
    sub,
    timestamp: Date.now(),
  };
  if (wantClaims) signedPayload.claims = { name: 'Ada Lovelace', picture: 'data:image/svg+xml,<svg/>' };
  const signedToken = b64(ed25519.sign(new TextEncoder().encode(canonicalJson(signedPayload)), priv));

  // 4. POST straight to the PUBLIC callback (what a phone on any network does).
  const cb = await fetch(cfg.callbackUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: publicKeyB64, signedPayload, signedToken }),
  });
  console.log('callback:', cb.status, await cb.json().catch(() => ({})));

  // 5. Poll the LOCAL status (fed by the local server's Firestore listener).
  let status = {};
  for (let i = 0; i < 15; i++) {
    status = await (await fetch(`${LOCAL}/kunji/status?sessionId=${session.sessionId}`)).json();
    if (status.status === 'approved') break;
    await sleep(400);
  }
  console.log('\nlocal status:', status.status);
  console.log('  sub   :', status.sub);
  console.log('  claims:', status.claims || '(none — RP uses the default identity)');
};

main().catch((e) => {
  console.error('relay wallet-sim failed:', e.message);
  console.error('Is the Function deployed and `npm start` running?');
  process.exit(1);
});
