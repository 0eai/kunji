import { onRequest } from 'firebase-functions/v2/https';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, Timestamp } from 'firebase-admin/firestore';
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

// Global cap on FAILED code lookups — defense-in-depth against distributed code
// brute-force (per-IP limiting is XFF-spoofable). Only failures count, so legitimate
// valid-code lookups never trip it.
const GLOBAL_FAIL_REF = () => db.collection('rateLimits').doc('global_code_failures');
const globalFailuresExceeded = async (max = 60, windowMs = 60 * 1000) => {
  const snap = await GLOBAL_FAIL_REF().get();
  const d = snap.exists ? snap.data() : null;
  return !!d && (Date.now() - d.start <= windowMs) && d.count >= max;
};
const bumpGlobalFailure = async (windowMs = 60 * 1000) => {
  const ref = GLOBAL_FAIL_REF();
  const now = Date.now();
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const d = snap.exists ? snap.data() : null;
    if (!d || now - d.start > windowMs) tx.set(ref, { start: now, count: 1 });
    else tx.update(ref, { count: d.count + 1 });
  });
};

// Create a login session.
// ⚠️ DEMO ONLY: this reads audience + callbackUrl from the request body so the demo
// frontend can supply them. A PRODUCTION relying party MUST hardcode its own audience
// and callbackUrl server-side and ignore the body — otherwise a caller can mint
// sessions claiming an arbitrary domain.
export const createSession = onRequest({ cors: true }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const { audience, callbackUrl } = req.body || {};
  if (!audience || !callbackUrl) return res.status(400).json({ error: 'audience and callbackUrl required' });

  const sessionId = hex(16);
  const challenge = hex(32);
  const code = await freshCode();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  // `ttl` lets Firestore's TTL policy auto-delete the doc ~5 min after expiry,
  // so loginSessions never grows unbounded.
  const ttl = Timestamp.fromMillis(expiresAt + 5 * 60 * 1000);
  await sessionRef(sessionId).set({ challenge, audience, callbackUrl, code, status: 'pending', sub: null, expiresAt, ttl });
  res.json({ sessionId, challenge, code, expiresAt });
});

// Device-authorization: kunji resolves a 6-digit code to the pending session so it
// can sign the challenge. Returns the challenge/callback (NOT an approval).
export const lookupSession = onRequest({ cors: true }, async (req, res) => {
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  if (await globalFailuresExceeded()) return res.status(429).json({ error: 'rate_limited' });

  const code = String(req.query.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'bad_code' });

  const q = await db.collection('loginSessions').where('code', '==', code).limit(1).get();
  const doc = q.docs[0];
  const s = doc?.data();
  if (!doc || s.status !== 'pending') { await bumpGlobalFailure(); return res.status(404).json({ error: 'invalid_code' }); }
  if (Date.now() > s.expiresAt) return res.status(410).json({ error: 'expired_code' });

  res.json({ sessionId: doc.id, challenge: s.challenge, audience: s.audience, callbackUrl: s.callbackUrl, expiresAt: s.expiresAt });
});

// Poll endpoint for the drop-in widget (rp.js): resolve a sessionId to its status.
// Read-only; the doc holds no secrets (just status + the per-app sub).
export const getSessionStatus = onRequest({ cors: true }, async (req, res) => {
  const sessionId = String(req.query.sessionId || '');
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  const snap = await sessionRef(sessionId).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_session' });
  const s = snap.data();
  res.json({ status: s.status, sub: s.sub || null });
});

// The wallet POSTs the signed assertion here (spec §5.2). Full §6 verification.
export const kunjiCallback = onRequest({ cors: true }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  if (!sessionId) return res.status(400).json({ error: 'malformed_assertion' });
  const ref = sessionRef(sessionId);

  try {
    // Verify + consume atomically so a captured/duplicated assertion can't approve
    // the same session twice (single-use, spec §6.7).
    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const session = snap.exists ? snap.data() : null;
      const r = verifyAssertion({ assertion, session, audience: session?.audience });
      if (!r.ok) return r;
      if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
      tx.update(ref, { status: 'approved', sub: r.sub });
      return r;
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ error: 'callback_failed' });
  }
});
