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
// Reuse kunji's shared default-identity helper for a friendly printout. A real RP would
// use window.kunji.handle(sub) from rp.js (see public/index.html).
import { deriveHandle } from '../../src/lib/kunjiHandle.js';

const BASE = process.env.BASE || 'http://localhost:3000';
const wantClaims = process.argv.includes('--claims');
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
};

main().catch((e) => {
  console.error('wallet-sim failed:', e.message);
  console.error('Is the server running?  npm start');
  process.exit(1);
});
