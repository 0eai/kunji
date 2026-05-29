import express from 'express';
import { randomBytes } from 'node:crypto';
import { verifyAssertion } from './verify.js';

const PORT = process.env.PORT || 8787;
const SESSION_TTL_MS = 2 * 60 * 1000; // 2 minutes

// In-memory session store (a real RP would use its own DB). No kunji DB involved.
const sessions = new Map();

const app = express();
app.use(express.json({ limit: '64kb' }));

// Permissive CORS — the kunji wallet POSTs the assertion from its own origin.
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const hex = (n) => randomBytes(n).toString('hex');

// 1. Create a login session. The frontend supplies the audience + callbackUrl
//    it will encode into the QR. (A production RP would hardcode its own domain.)
app.post('/api/session', (req, res) => {
  const { audience, callbackUrl, appName, iconUrl } = req.body || {};
  if (!audience || !callbackUrl) return res.status(400).json({ error: 'audience and callbackUrl required' });

  const sessionId = hex(16);
  const challenge = hex(32);
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sessionId, { challenge, audience, callbackUrl, appName, iconUrl, status: 'pending', sub: null, expiresAt });

  res.json({ sessionId, challenge, expiresAt });
});

// 2. The wallet POSTs the signed assertion here (spec §5.2). Full §6 verification.
app.post('/kunji/callback', (req, res) => {
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  const session = sessionId ? sessions.get(sessionId) : null;

  const result = verifyAssertion({ assertion, session, audience: session?.audience });
  if (!result.ok) return res.status(400).json({ error: result.error });

  session.status = 'approved';
  session.sub = result.sub;
  res.json({ status: 'ok' });
});

// 3. The frontend polls here for the result.
app.get('/api/session/:id', (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.json({ status: 'unknown' });
  if (s.status === 'pending' && Date.now() > s.expiresAt) return res.json({ status: 'expired' });
  res.json({ status: s.status, sub: s.status === 'approved' ? s.sub : undefined });
});

// Periodic cleanup of stale sessions.
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now > s.expiresAt + 60_000) sessions.delete(id);
  }
}, 60_000).unref?.();

app.listen(PORT, () => {
  console.log(`[kunji-login-demo] RP backend on http://localhost:${PORT}`);
});
