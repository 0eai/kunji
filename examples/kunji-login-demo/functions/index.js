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

// Create a login session. The frontend supplies the audience + callbackUrl it will
// encode into the QR. (A production RP would hardcode its own domain server-side.)
export const createSession = onRequest({ cors: true }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const { audience, callbackUrl } = req.body || {};
  if (!audience || !callbackUrl) return res.status(400).json({ error: 'audience and callbackUrl required' });

  const sessionId = hex(16);
  const challenge = hex(32);
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await sessionRef(sessionId).set({ challenge, audience, callbackUrl, status: 'pending', sub: null, expiresAt });
  res.json({ sessionId, challenge, expiresAt });
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
