import { onRequest } from 'firebase-functions/v2/https';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import { randomBytes } from 'node:crypto';
import { verifyAssertion } from './verify.js';

initializeApp();
const db = getFirestore();
const SESSION_TTL_MS = 2 * 60 * 1000;
const hex = (n) => randomBytes(n).toString('hex');
const sessionRef = (id) => db.collection('loginSessions').doc(id);

// A globally-unique 6-digit code (equality-only query → no composite index needed).
const freshCode = async () => {
  for (let i = 0; i < 8; i++) {
    const code = String(Math.floor(100000 + (randomBytes(4).readUInt32BE(0) % 900000)));
    const dup = await db.collection('loginSessions').where('code', '==', code).limit(1).get();
    if (dup.empty) return code;
  }
  throw new Error('code_alloc_failed');
};

// Per-IP sliding-window rate limit (protects the 6-digit code space).
const rateLimited = async (ip, max = 10, windowMs = 60 * 1000) => {
  const ref = db.collection('rateLimits').doc(`lookup_${(ip || 'unknown').replace(/[^\w.:-]/g, '_')}`);
  const now = Date.now();
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const d = snap.exists ? snap.data() : null;
    if (!d || now - d.start > windowMs) { tx.set(ref, { start: now, count: 1 }); return false; }
    if (d.count >= max) return true;
    tx.update(ref, { count: d.count + 1 });
    return false;
  });
};

// Create a login session. The frontend supplies the audience + callbackUrl it will
// encode into the QR. (A production RP would hardcode its own domain server-side.)
export const createSession = onRequest({ cors: true }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const { audience, callbackUrl } = req.body || {};
  if (!audience || !callbackUrl) return res.status(400).json({ error: 'audience and callbackUrl required' });

  const sessionId = hex(16);
  const challenge = hex(32);
  const code = await freshCode();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await sessionRef(sessionId).set({ challenge, audience, callbackUrl, code, status: 'pending', sub: null, expiresAt });
  res.json({ sessionId, challenge, code, expiresAt });
});

// Device-authorization: kunji resolves a 6-digit code to the pending session so it
// can sign the challenge. Returns the challenge/callback (NOT an approval).
export const lookupSession = onRequest({ cors: true }, async (req, res) => {
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  const code = String(req.query.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'bad_code' });

  const q = await db.collection('loginSessions').where('code', '==', code).limit(1).get();
  const doc = q.docs[0];
  if (!doc) return res.status(404).json({ error: 'invalid_code' });
  const s = doc.data();
  if (s.status !== 'pending') return res.status(404).json({ error: 'invalid_code' });
  if (Date.now() > s.expiresAt) return res.status(410).json({ error: 'expired_code' });

  res.json({ sessionId: doc.id, challenge: s.challenge, audience: s.audience, callbackUrl: s.callbackUrl, expiresAt: s.expiresAt });
});

// The wallet POSTs the signed assertion here (spec §5.2). Full §6 verification.
export const kunjiCallback = onRequest({ cors: true }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  const ref = sessionId ? sessionRef(sessionId) : null;
  const snap = ref ? await ref.get() : null;
  const session = snap?.exists ? snap.data() : null;

  const result = verifyAssertion({ assertion, session, audience: session?.audience });
  if (!result.ok) return res.status(400).json({ error: result.error });

  await ref.update({ status: 'approved', sub: result.sub });
  res.json({ status: 'ok' });
});
