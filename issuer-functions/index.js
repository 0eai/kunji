// kunji credential ISSUER — Cloud Functions for issuer.kunji.cc (Functions codebase `issuer`, isolated from
// the wallet's `app` codebase). A separate origin with its own KUNJI_ISSUER_SIGNING_KEY secret (a
// rotation-capable key set), namespaced `issuer*`/`verification*` Firestore, and a verifier that fetches THIS
// origin's `.well-known` cross-origin. SD-JWT VC only.
//
// kunji's OWN verification flow (pluggable): a credential TYPE (credentials.js) is verified by a METHOD
// (verify/). MVP method = document-review (the user uploads a government ID, an operator reviews it + confirms
// the DOB in the admin console, then we mint). Future methods (PASS, Aadhaar, …) slot into the same flow.
// PROOFING GATE: a credential offer is minted ONLY for a `verified` verificationSession (or, for dev only,
// ISSUER_OPEN_MINT=true). See ../docs/issuer.md.
import { onRequest } from 'firebase-functions/v2/https';
import { onSchedule } from 'firebase-functions/v2/scheduler';
import { defineSecret } from 'firebase-functions/params';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, Timestamp } from 'firebase-admin/firestore';
import { getAuth } from 'firebase-admin/auth';
import { getStorage } from 'firebase-admin/storage';
import { randomBytes } from 'node:crypto';
import { verifyProofJwt } from './oid4vc.js';
import { loadKeySet, issuerWellKnown, credentialIssuerMetadata, authServerMetadata, mintTypedCredential, MAX_BATCH } from './issuer.js';
import { ISSUER_BRAND, CREDENTIAL_TYPES, getType } from './credentials.js';
import { getMethod } from './verify/index.js';
import { verifyAssertion } from './loginVerify.js';

const ISSUER_ORIGIN = process.env.ISSUER_ORIGIN || 'https://issuer-kunji-cc.web.app';
const STORAGE_BUCKET = process.env.STORAGE_BUCKET || 'kunji-cc.firebasestorage.app';
initializeApp({ storageBucket: STORAGE_BUCKET });
const db = getFirestore();
const bucket = () => getStorage().bucket();

// Distinct from the kunji-demo's `ISSUER_SIGNING_KEY`: Firebase Secrets are PROJECT-scoped and both codebases
// live in kunji-cc, so reusing that name would make the REAL issuer sign with the demo's (mints-to-anyone) key.
const ISSUER_SIGNING_KEY = defineSecret('KUNJI_ISSUER_SIGNING_KEY');
// Dev-only escape: mint without a verification (default OFF). Production issues only after a verified session.
const OPEN_MINT = process.env.ISSUER_OPEN_MINT === 'true';

const ISSUER_HOST = (() => {
  try {
    return new URL(ISSUER_ORIGIN).host;
  } catch {
    return 'issuer.kunji.cc';
  }
})();
const VC_TTL_MS = 5 * 60 * 1000;
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000; // a verification session (incl. pending review) lives a day
const DOC_MAX_AGE_MS = 24 * 60 * 60 * 1000; // abandoned ID images are swept after this
const LOGIN_TTL_MS = 5 * 60 * 1000; // a kunji-login session
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // an issuer session (bearer → sub) lives 30 days
const vcOpts = (secrets) => ({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30, secrets });
const ttlAfter = (ms) => Timestamp.fromMillis(Date.now() + ms + 5 * 60 * 1000);
const token = (n) => randomBytes(n).toString('base64url');
const keySet = () => loadKeySet(ISSUER_SIGNING_KEY.value());

// Reserve `n` contiguous StatusList indices for credential `type` in a transaction (per-type idx space).
const allocStatusIdxs = async (type, n) => {
  const ref = db.collection('issuerStatusList').doc(type);
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const start = (snap.exists && snap.data().nextIdx) || 1;
    tx.set(ref, { nextIdx: start + n }, { merge: true });
    return Array.from({ length: n }, (_, i) => start + i);
  });
};
// StatusList check: an idx is valid unless an admin added it to the type's `revoked` list.
const checkStatus = async (type, idx) => {
  const snap = await db.collection('issuerStatusList').doc(type).get();
  const revoked = (snap.exists && snap.data().revoked) || [];
  return !revoked.includes(Number(idx)); // false ⇒ revoked
};

// Per-IP sliding-window rate limit on the public endpoints (namespaced `issuerRateLimits`).
const rateLimited = async (ip, max = 30, windowMs = 60 * 1000) => {
  const ref = db.collection('issuerRateLimits').doc(`${(ip || 'unknown').replace(/[^\w.:-]/g, '_')}`);
  const now = Date.now();
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const d = snap.exists ? snap.data() : null;
    if (!d || now - d.start > windowMs) {
      tx.set(ref, { start: now, count: 1 });
      return false;
    }
    if (d.count >= max) return true;
    tx.update(ref, { count: d.count + 1 });
    return false;
  });
};

// ── Catalog (drives the multi-credential UI) — type → provider, from the registries ──
// UI-shaped (separate from the OID4VCI .well-known, which stays spec-clean). `coming_soon` entries are
// display-only (never startable — /verify/start validates against the registered methods).
const catalog = () => ({
  brand: ISSUER_BRAND,
  types: Object.entries(CREDENTIAL_TYPES).map(([id, t]) => ({
    id,
    label: t.label,
    description: t.description || null,
    reviewFields: t.reviewFields || [],
    methods: [
      ...t.methods.map((mid) => {
        const m = getMethod(mid) || {};
        return { id: mid, label: m.label || mid, description: m.description || null, region: m.region || 'global', kind: m.kind || 'manual', status: m.status || 'available' };
      }),
      ...(t.comingSoon || []).map((c) => ({ id: c.id, label: c.label, description: c.description || null, region: c.region || 'global', status: 'coming_soon' })),
    ],
  })),
});
export const issuerCatalog = onRequest(vcOpts([]), (_req, res) => res.json(catalog()));

// ── Login with kunji (RP) — bind a verification to the user's per-app `sub` so it survives refresh /
// tab-close / device change. Reuses the discoverable-login assertion verifier (loginVerify.js); the
// audience is HARDCODED to this issuer's host (never read from the request body). See docs/discoverable-login.md.
const loginRef = (id) => db.collection('issuerLoginSessions').doc(id);

// A globally-unique 6-digit code (equality query → single-field index).
const freshCode = async () => {
  for (let i = 0; i < 8; i++) {
    const code = String(Math.floor(100000 + (randomBytes(4).readUInt32BE(0) % 900000)));
    const dup = await db.collection('issuerLoginSessions').where('code', '==', code).limit(1).get();
    if (dup.empty) return code;
  }
  throw new Error('code_alloc_failed');
};

// Bearer issuer-session token (minted on login approval) → the user's per-app `sub` (or null).
const requireUser = async (req) => {
  const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return null;
  const snap = await db.collection('issuerSessions').doc(m[1]).get();
  const d = snap.exists ? snap.data() : null;
  if (!d || (d.expiresAt && Date.now() > d.expiresAt)) return null;
  return d.sub || null;
};

// /kunji/session — POST creates a login session (the issuer page renders its QR + 6-digit code; audience
// HARDCODED to ISSUER_HOST). GET ?code= is the wallet's device-authorization lookup (it calls
// GET https://{domain}/kunji/session?code= per identity.js lookupSessionByCode) → resolves the code.
export const kunjiLoginSession = onRequest(vcOpts([]), async (req, res) => {
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  if (req.method === 'GET') {
    const code = String(req.query.code || '');
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'bad_code' });
    const q = await db.collection('issuerLoginSessions').where('code', '==', code).limit(1).get();
    const doc = q.docs[0];
    const s = doc?.data();
    if (!doc || s.status !== 'pending') return res.status(404).json({ error: 'invalid_code' });
    if (Date.now() > s.expiresAt) return res.status(410).json({ error: 'expired_code' });
    return res.json({ sessionId: doc.id, challenge: s.challenge, audience: s.audience, callbackUrl: `${ISSUER_ORIGIN}/kunji/callback`, expiresAt: s.expiresAt });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const sessionId = token(16);
  const challenge = token(32);
  const code = await freshCode();
  const expiresAt = Date.now() + LOGIN_TTL_MS;
  await loginRef(sessionId).set({ challenge, audience: ISSUER_HOST, code, status: 'pending', expiresAt, ttl: ttlAfter(LOGIN_TTL_MS) });
  res.json({ sessionId, challenge, audience: ISSUER_HOST, code, expiresAt, callbackUrl: `${ISSUER_ORIGIN}/kunji/callback` });
});

// POST /kunji/callback ← the wallet's signed assertion. §6 verify (audience hardcoded) + consume, then mint
// an issuer-session token (bearer → sub).
export const kunjiLoginCallback = onRequest(vcOpts([]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  if (!sessionId) return res.status(400).json({ error: 'malformed_assertion' });
  const ref = loginRef(sessionId);
  try {
    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const session = snap.exists ? snap.data() : null;
      const r = verifyAssertion({ assertion, session, audience: ISSUER_HOST }); // §6; audience hardcoded
      if (!r.ok) return r;
      if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
      const sessionToken = token(24);
      tx.update(ref, { status: 'approved', sub: r.sub, sessionToken });
      tx.set(db.collection('issuerSessions').doc(sessionToken), { sub: r.sub, expiresAt: Date.now() + SESSION_TTL_MS, ttl: ttlAfter(SESSION_TTL_MS) });
      tx.set(db.collection('issuerUsers').doc(r.sub), { lastLoginAt: Date.now() }, { merge: true });
      return r;
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ error: 'callback_failed' });
  }
});

// GET /kunji/status?sessionId → poll; returns the issuer-session token once approved.
export const kunjiLoginStatus = onRequest(vcOpts([]), async (req, res) => {
  const snap = await loginRef(String(req.query.sessionId || '')).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_session' });
  const s = snap.data();
  res.json({ status: s.status, sessionToken: s.status === 'approved' ? s.sessionToken : null });
});

// ── Verification flow (kunji's own) — start → (method-specific) → verified ──
// POST /verify/start { type, method } → create a session. A 'manual' method (document-review) awaits an
// upload ('collecting'); future 'redirect'/'inline' methods would start the provider and return a url.
export const issuerVerifyStart = onRequest(vcOpts([]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  const sub = await requireUser(req);
  if (!sub) return res.status(401).json({ error: 'login_required' });
  const { type, method } = req.body || {};
  const t = getType(type);
  const m = getMethod(method);
  if (!t || !m || !t.methods.includes(method)) return res.status(400).json({ error: 'unsupported' });
  const sid = token(24);
  const status = m.kind === 'manual' ? 'collecting' : 'pending_review';
  await db.collection('verificationSessions').doc(sid).set({ sub, type, method, status, ttl: ttlAfter(VERIFY_TTL_MS) });
  res.json({ sid, kind: m.kind });
});

// POST /verify/upload { sid, image (base64/dataURL), contentType } → store the ID image (Admin SDK, private)
// and move the session to 'pending_review'. The image is deleted on the admin's decision (data minimization).
export const issuerVerifyUpload = onRequest(vcOpts([]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  if (await rateLimited(req.ip, 10)) return res.status(429).json({ error: 'rate_limited' });
  const sub = await requireUser(req);
  if (!sub) return res.status(401).json({ error: 'login_required' });
  const { sid, image, contentType } = req.body || {};
  const ref = db.collection('verificationSessions').doc(String(sid || ''));
  const snap = await ref.get();
  const session = snap.exists ? snap.data() : null;
  if (!session || session.status !== 'collecting' || session.sub !== sub) return res.status(409).json({ error: 'bad_session' });
  const m = getMethod(session.method);
  if (!m || m.kind !== 'manual') return res.status(400).json({ error: 'unsupported' });
  let buf;
  try {
    buf = Buffer.from(String(image || '').replace(/^data:[^;]+;base64,/, ''), 'base64');
  } catch {
    return res.status(400).json({ error: 'bad_image' });
  }
  if (!m.validateUpload({ contentType, bytes: buf.length })) return res.status(400).json({ error: 'bad_image' });
  const docPath = `verify-docs/${sid}`;
  await bucket().file(docPath).save(buf, { contentType, resumable: false, metadata: { cacheControl: 'no-store' } });
  await ref.update({ status: 'pending_review', docPath, docContentType: contentType, submittedAt: Date.now() });
  res.json({ status: 'pending_review' });
});

// GET /verify/status?sid → the issuer page polls this; returns only the non-privileged status.
export const issuerVerifyStatus = onRequest(vcOpts([]), async (req, res) => {
  const snap = await db.collection('verificationSessions').doc(String(req.query.sid || '')).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_session' });
  res.json({ status: snap.data().status || 'collecting' });
});

// GET /verify/mine → the signed-in user's active verifications, so a returning user resumes (across refresh /
// tab-close / device — re-login yields the same `sub`). Authed.
export const issuerVerifyMine = onRequest(vcOpts([]), async (req, res) => {
  const sub = await requireUser(req);
  if (!sub) return res.status(401).json({ error: 'login_required' });
  const snap = await db.collection('verificationSessions').where('sub', '==', sub).limit(20).get();
  const items = snap.docs
    .map((d) => ({ sid: d.id, ...d.data() }))
    .filter((x) => ['collecting', 'pending_review', 'verified'].includes(x.status))
    .map((x) => ({ sid: x.sid, type: x.type, method: x.method, status: x.status }));
  res.json({ items });
});

// ── Issuer metadata + trust anchor (the key SET + brand a verifier fetches cross-origin) ──
export const issuerOidcMetadata = onRequest(vcOpts([]), (_req, res) => res.json(credentialIssuerMetadata(ISSUER_ORIGIN)));
export const issuerOauthMetadata = onRequest(vcOpts([]), (_req, res) => res.json(authServerMetadata(ISSUER_ORIGIN)));
export const issuerKeys = onRequest(vcOpts([ISSUER_SIGNING_KEY]), (_req, res) => res.json(issuerWellKnown(ISSUER_ORIGIN, keySet())));

// ── OpenID4VCI: offer → token → credential ──
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

// GET /credential-offer?sid → mint a single-use pre-authorized_code bound to a VERIFIED session's type+claims
// (and consume the session). Without a sid, only the dev OPEN_MINT path; otherwise closed (503).
export const issuerOffer = onRequest(vcOpts([]), async (req, res) => {
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  const sid = String(req.query.sid || '');
  let type = null;
  let claims = null;
  if (sid) {
    const sub = await requireUser(req);
    if (!sub) return res.status(401).json({ error: 'login_required' });
    const verified = await db.runTransaction(async (tx) => {
      const ref = db.collection('verificationSessions').doc(sid);
      const snap = await tx.get(ref);
      const d = snap.exists ? snap.data() : null;
      if (!d || d.status !== 'verified' || d.sub !== sub) return null;
      tx.delete(ref); // consume: one verified session ⇒ one offer/batch
      return d;
    });
    if (!verified) return res.status(403).json({ error: 'not_verified' });
    type = verified.type;
    claims = verified.claims || null;
  } else if (OPEN_MINT) {
    type = 'age';
    claims = getType('age').buildClaims({ age: 30 }); // dev-only test path
  } else {
    return res.status(503).json({ error: 'issuance_not_enabled' });
  }
  if (!getType(type) || !claims) return res.status(400).json({ error: 'unsupported' });
  const code = token(24);
  await db.collection('issuerOffers').doc(code).set({ type, claims, ttl: ttlAfter(VC_TTL_MS) });
  const offer = {
    credential_issuer: ISSUER_ORIGIN,
    credential_configuration_ids: [type],
    grants: { [PRE_AUTH_GRANT]: { 'pre-authorized_code': code } },
  };
  res.json({ offer, offerUri: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}` });
});

// POST /token → redeem the pre-authorized_code (single-use) for an access_token + c_nonce, carrying the
// session's type+claims so /credential mints exactly what was verified.
export const issuerTokenEndpoint = onRequest(vcOpts([]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  if (req.body?.grant_type !== PRE_AUTH_GRANT) return res.status(400).json({ error: 'unsupported_grant_type' });
  const code = req.body['pre-authorized_code'];
  const offer = await db.runTransaction(async (tx) => {
    const ref = db.collection('issuerOffers').doc(String(code || ''));
    const snap = await tx.get(ref);
    if (!snap.exists) return null;
    tx.delete(ref); // single-use
    return snap.data();
  });
  if (!offer) return res.status(400).json({ error: 'invalid_grant' });
  const access_token = token(24);
  const cNonce = token(24);
  await db.collection('issuerTokens').doc(access_token).set({ cNonce, type: offer.type, claims: offer.claims || null, ttl: ttlAfter(VC_TTL_MS) });
  res.json({ access_token, token_type: 'bearer', expires_in: 300, c_nonce: cNonce, c_nonce_expires_in: 300 });
});

// POST /credential → verify the holder proof JWT(s) (single-use token) and mint the SD-JWT VC(s) of the
// session's type. Writes a data-minimized ledger row per copy (the booleans + idx + kid — never a DOB/image).
export const issuerCredentialEndpoint = onRequest(vcOpts([ISSUER_SIGNING_KEY]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const tok = /^(?:DPoP|Bearer) (.+)$/.exec(String(req.headers.authorization || ''))?.[1];
  const consumed = await db.runTransaction(async (tx) => {
    const ref = db.collection('issuerTokens').doc(String(tok || ''));
    const snap = await tx.get(ref);
    if (!snap.exists) return null;
    tx.delete(ref); // single-use
    return snap.data();
  });
  if (!consumed) return res.status(401).json({ error: 'invalid_token' });
  const type = consumed.type || 'age';
  const t = getType(type);
  const claims = consumed.claims || null;
  if (!t || !claims) return res.status(400).json({ error: 'unsupported' });
  const fmt = req.body?.format;
  if (fmt && fmt !== 'vc+sd-jwt' && fmt !== 'dc+sd-jwt') return res.status(400).json({ error: 'unsupported_credential_format' });
  const typ = fmt === 'dc+sd-jwt' ? fmt : undefined;
  const ks = keySet();

  // Batch (unlinkability v2): one one-time copy per holder key. `proof` is the pre-batch fallback.
  const batch = req.body?.proofs?.jwt;
  const proofs = Array.isArray(batch) && batch.length ? batch : req.body?.proof?.jwt ? [req.body.proof.jwt] : [];
  if (!proofs.length) return res.status(400).json({ error: 'invalid_proof' });
  if (proofs.length > MAX_BATCH) return res.status(400).json({ error: 'batch_too_large', max: MAX_BATCH });
  const holderJwks = [];
  for (const jwt of proofs) {
    const v = verifyProofJwt({ proofJwt: jwt, audience: ISSUER_ORIGIN, cNonce: consumed.cNonce });
    if (!v.ok) return res.status(400).json({ error: 'invalid_proof', detail: v.error });
    holderJwks.push(v.holderJwk);
  }
  const idxs = await allocStatusIdxs(type, holderJwks.length);
  const creds = holderJwks.map((holderJwk, i) => mintTypedCredential({ keySet: ks, origin: ISSUER_ORIGIN, type, holderJwk, idx: idxs[i], claims, typ }));
  const issuedAt = Date.now();
  await Promise.all(
    idxs.map((idx) =>
      db.collection('issuerCredentials').doc(`${type}_${idx}`).set({ vct: t.vct, type, idx, kid: ks.active.kid, claims, issuedAt }),
    ),
  );
  res.json(Array.isArray(batch) && batch.length ? { credentials: creds } : { credential: creds[0] });
});

// GET /status/{type}?idx= → StatusList check (a verifier's checkStatus honors valid:false as revoked).
export const issuerStatusEndpoint = onRequest(vcOpts([]), async (req, res) => {
  const type = req.path.split('/')[2] || 'age';
  res.json({ valid: await checkStatus(type, req.query.idx) });
});

// ── Admin console API (admin.kunji.cc) — operator-only: review queue, ledger, revoke, stats ──
// THE GATE IS THE `admin:true` CUSTOM CLAIM, not authentication: this same project mints anonymous wallet
// tokens, which verifyIdToken would accept — so a token without the claim must be rejected. The admin API
// holds NO signing secret (keys are read from the public .well-known), so it cannot sign or rotate keys.
const requireAdmin = async (req) => {
  const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return null;
  try {
    const decoded = await getAuth().verifyIdToken(m[1]);
    return decoded.admin === true ? decoded : null;
  } catch {
    return null;
  }
};

// Pending-review queue (oldest first). No PII — just sid/type/method/submittedAt; the image is fetched lazily.
const adminReviews = async () => {
  const snap = await db.collection('verificationSessions').where('status', '==', 'pending_review').limit(100).get();
  const items = snap.docs
    .map((d) => ({ sid: d.id, ...d.data() }))
    .map((x) => ({
      sid: x.sid,
      type: x.type,
      method: x.method,
      submittedAt: x.submittedAt || null,
      // The fields the operator must confirm for this type (drives the dynamic review panel).
      reviewFields: getType(x.type)?.reviewFields || [],
    }))
    .sort((a, b) => (a.submittedAt || 0) - (b.submittedAt || 0));
  return { items };
};

// Stream the pending session's ID image to the (already claim-verified) operator — never a public URL.
const adminReviewDoc = async (sid, res) => {
  const snap = await db.collection('verificationSessions').doc(String(sid || '')).get();
  const s = snap.exists ? snap.data() : null;
  if (!s || !s.docPath) return res.status(404).json({ error: 'no_document' });
  const [buf] = await bucket().file(s.docPath).download();
  res.set('Content-Type', s.docContentType || 'application/octet-stream');
  res.set('Cache-Control', 'no-store');
  return res.send(buf);
};

// Approve (with the reviewer-confirmed fields) → verified + claims; or reject. Either way DELETE the ID
// image. `verifiedData` is the type's reviewFields the operator filled in; a bare `dob` is accepted for
// back-compat with the original age flow. buildClaims is the no-PII boundary: raw inputs → coarse claims.
const adminReviewDecision = async (admin, { sid, approve, verifiedData, dob }) => {
  const data = verifiedData && typeof verifiedData === 'object' ? verifiedData : dob != null ? { dob } : {};
  const ref = db.collection('verificationSessions').doc(String(sid || ''));
  const result = await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const s = snap.exists ? snap.data() : null;
    if (!s || s.status !== 'pending_review') return { error: 'bad_session' };
    if (!approve) {
      tx.update(ref, { status: 'rejected', reviewer: admin.email || admin.uid, reviewedAt: Date.now(), docPath: null });
      return { docPath: s.docPath, status: 'rejected' };
    }
    const claims = getType(s.type)?.buildClaims(data);
    if (!claims) return { error: 'bad_claims' };
    tx.update(ref, { status: 'verified', claims, reviewer: admin.email || admin.uid, reviewedAt: Date.now(), docPath: null });
    return { docPath: s.docPath, status: 'verified' };
  });
  if (result.error) throw new Error(result.error);
  if (result.docPath) await bucket().file(result.docPath).delete({ ignoreNotFound: true }).catch(() => {});
  return { status: result.status };
};

// Issuance ledger, newest first (by issuedAt — idx is per-type), each flagged with its revocation status.
const adminLedger = async (req) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const before = Number(req.query.before);
  let q = db.collection('issuerCredentials').orderBy('issuedAt', 'desc');
  if (Number.isInteger(before) && before > 0) q = q.where('issuedAt', '<', before).orderBy('issuedAt', 'desc');
  const snap = await q.limit(limit).get();
  const items = await Promise.all(
    snap.docs.map(async (d) => {
      const x = d.data();
      const valid = await checkStatus(x.type || 'age', x.idx);
      return { id: d.id, type: x.type || 'age', vct: x.vct, idx: x.idx, kid: x.kid, claims: x.claims || null, issuedAt: x.issuedAt || null, revoked: !valid };
    }),
  );
  return { items, nextBefore: items.length === limit ? items[items.length - 1].issuedAt : null };
};

// Aggregate stats (count() — no docs returned): the verification funnel + issuance/revocation totals.
const adminStats = async () => {
  const vs = db.collection('verificationSessions');
  const [collecting, pending, verified, rejected, issued] = await Promise.all([
    vs.where('status', '==', 'collecting').count().get(),
    vs.where('status', '==', 'pending_review').count().get(),
    vs.where('status', '==', 'verified').count().get(),
    vs.where('status', '==', 'rejected').count().get(),
    db.collection('issuerCredentials').count().get(),
  ]);
  const statusSnaps = await db.collection('issuerStatusList').get();
  const revoked = statusSnaps.docs.reduce((n, d) => n + ((d.data().revoked || []).length), 0);
  return {
    verification: { collecting: collecting.data().count, pending_review: pending.data().count, verified: verified.data().count, rejected: rejected.data().count },
    issued: issued.data().count,
    revoked,
  };
};

// Revoke / un-revoke an idx of `type` by toggling issuerStatusList/{type}.revoked (transaction; idempotent).
const adminSetRevoked = async (type, idx, revoke) => {
  const n = Number(idx);
  const t = getType(type);
  if (!t || !Number.isInteger(n) || n < 1) throw new Error('bad_idx');
  const ref = db.collection('issuerStatusList').doc(type);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const cur = new Set(((snap.exists && snap.data().revoked) || []).map(Number));
    if (revoke) cur.add(n);
    else cur.delete(n);
    tx.set(ref, { revoked: Array.from(cur) }, { merge: true });
  });
  return { type, idx: n, revoked: revoke };
};

// /api/** (admin.kunji.cc rewrite) — one Function, internal path router; same-origin (no CORS).
export const issuerAdminApi = onRequest({ cors: false, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  const admin = await requireAdmin(req);
  if (!admin) return res.status(401).json({ error: 'unauthorized' });
  try {
    if (req.method === 'GET' && req.path === '/api/ledger') return res.json(await adminLedger(req));
    if (req.method === 'GET' && req.path === '/api/stats') return res.json(await adminStats());
    if (req.method === 'GET' && req.path === '/api/reviews') return res.json(await adminReviews());
    if (req.method === 'GET' && req.path === '/api/review/doc') return await adminReviewDoc(req.query.sid, res);
    if (req.method === 'POST' && req.path === '/api/review/decision')
      return res.json(await adminReviewDecision(admin, req.body || {}));
    if (req.method === 'POST' && req.path === '/api/revoke') return res.json(await adminSetRevoked(req.body?.type || 'age', req.body?.idx, true));
    if (req.method === 'POST' && req.path === '/api/unrevoke') return res.json(await adminSetRevoked(req.body?.type || 'age', req.body?.idx, false));
    return res.status(404).json({ error: 'not_found' });
  } catch (e) {
    const known = ['bad_idx', 'bad_dob', 'bad_claims', 'bad_session'].includes(e?.message);
    return res.status(known ? 400 : 500).json({ error: known ? e.message : 'admin_failed' });
  }
});

// Daily sweep: delete abandoned ID images (uploaded but never reviewed) older than DOC_MAX_AGE_MS, so an ID
// document never lingers. Reviewed images are already deleted on the decision.
export const issuerCleanup = onSchedule({ schedule: 'every 24 hours', maxInstances: 1 }, async () => {
  const [files] = await bucket().getFiles({ prefix: 'verify-docs/' });
  const cutoff = Date.now() - DOC_MAX_AGE_MS;
  await Promise.all(
    files
      .filter((f) => new Date(f.metadata.timeCreated).getTime() < cutoff)
      .map((f) => f.delete({ ignoreNotFound: true }).catch(() => {})),
  );
});
