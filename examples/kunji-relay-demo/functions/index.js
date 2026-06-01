/**
 * kunjiCallback — the ONLY public piece of the relay demo.
 *
 * The phone's wallet POSTs the signed assertion here (public HTTPS, trusted cert — no
 * tunnel, no LAN cert). We run the full §6 verification AT THE EDGE (verify-in-Function:
 * most secure + cost-effective) and write the result to Firestore. The local RP server
 * never receives an inbound request — it listens to Firestore outbound — so its dynamic
 * IP behind NAT is irrelevant.
 *
 * Firestore rules are deny-all; only this Function (Admin SDK) and the local server's
 * Admin SDK touch the data, so an invalid assertion is rejected before anything is stored.
 */
import { onRequest } from 'firebase-functions/v2/https';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import { verifyAssertion } from './verify.js';

initializeApp();
const db = getFirestore();
const sessionRef = (id) => db.collection('relaySessions').doc(id);

export const kunjiCallback = onRequest({ cors: true }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  if (!sessionId) return res.status(400).json({ error: 'malformed_assertion' });
  const ref = sessionRef(sessionId);

  try {
    // Verify + consume atomically so a captured assertion can't approve twice (§6.7).
    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const session = snap.exists ? snap.data() : null;
      const r = verifyAssertion({ assertion, session, audience: session?.audience });
      if (!r.ok) return r;
      if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
      tx.update(ref, {
        status: 'approved',
        sub: r.sub,
        claims: r.claims || null,
        approvedAt: Date.now(),
      });
      return r;
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ error: 'callback_failed' });
  }
});
