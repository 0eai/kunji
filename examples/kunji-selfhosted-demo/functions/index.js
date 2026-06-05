/**
 * Self-hosted RP — the PUBLIC half (your own Firebase project).
 *
 * These functions are your front door: the browser creates a session, the wallet POSTs
 * the signed assertion to the callback, and on success we mint a Firebase **custom token**
 * (spec §7) so the user is genuinely authenticated to your Firestore as `uid = sub`. Your
 * dynamic-IP box (worker.js) never appears here — it reacts to Firestore changes outbound.
 *
 * Audience is **server-authoritative**: derived from the request host (your Hosting /
 * custom domain), never trusted from the client. Map a custom domain to this project so
 * the per-app `sub` is your real production identity.
 */
import { onRequest } from 'firebase-functions/v2/https';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { getAuth } from 'firebase-admin/auth';
import { randomBytes } from 'node:crypto';
import { verifyAssertion } from './verify.js';

initializeApp();
const db = getFirestore();
const SESSION_TTL_MS = 2 * 60 * 1000;
const hex = (n) => randomBytes(n).toString('hex');
const sessionRef = (id) => db.collection('loginSessions').doc(id);
// The audience we sign/verify = our own host (custom domain in prod), not the client's word.
const audienceOf = (req) => String(req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0];

export const createSession = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const audience = audienceOf(req);
  if (!audience) return res.status(400).json({ error: 'no_host' });
  const sessionId = hex(16);
  const challenge = hex(32);
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await sessionRef(sessionId).set({
    challenge,
    audience,
    status: 'pending',
    sub: null,
    claims: null,
    customToken: null,
    expiresAt,
    ttl: new Date(expiresAt + 5 * 60 * 1000), // add a Firestore TTL policy on `ttl`
  });
  res.json({ sessionId, challenge, audience, expiresAt });
});

export const kunjiCallback = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  if (!sessionId) return res.status(400).json({ error: 'malformed_assertion' });
  const ref = sessionRef(sessionId);

  try {
    // 1. Verify §6 and atomically RESERVE the session (pending → verifying) so a
    //    duplicate/replayed assertion can't be used twice (single-use, §6.7).
    const reserved = await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const session = snap.exists ? snap.data() : null;
      const r = verifyAssertion({ assertion, session, audience: session?.audience });
      if (!r.ok) return r;
      if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
      tx.update(ref, { status: 'verifying', sub: r.sub, claims: r.claims || null });
      return r;
    });
    if (!reserved.ok) return res.status(400).json({ error: reserved.error });

    // 2. Upsert the real account keyed by `sub`, and mint a Firebase custom token (§7).
    const userRef = db.collection('users').doc(reserved.sub);
    const userSnap = await userRef.get();
    await userRef.set(
      {
        sub: reserved.sub,
        lastLoginAt: Date.now(),
        lastClaims: reserved.claims || null,
        ...(userSnap.exists ? {} : { createdAt: FieldValue.serverTimestamp() }),
      },
      { merge: true },
    );
    const customToken = await getAuth().createCustomToken(reserved.sub, {
      kunjiPub: assertion.publicKey,
    });

    // 3. Publish the result — only now flip to `approved`, so a poller that sees
    //    `approved` is guaranteed the token is present.
    await ref.update({ status: 'approved', customToken });
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ error: 'callback_failed' });
  }
});

export const getSessionStatus = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  const snap = await sessionRef(String(req.query.sessionId || '')).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_session' });
  const s = snap.data();
  // `verifying` is internal — surface it as still pending to the client.
  const status = s.status === 'approved' ? 'approved' : 'pending';
  res.json({
    status,
    sub: status === 'approved' ? s.sub : null,
    claims: status === 'approved' ? s.claims || null : null,
    customToken: status === 'approved' ? s.customToken || null : null,
  });
});
