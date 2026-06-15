// kunji age-credential ISSUER — Cloud Functions for issuer.kunji.cc (Functions codebase `issuer`, isolated
// from the wallet's `app` codebase). This is the REAL issuer: a separate origin, its own ISSUER_SIGNING_KEY
// secret (a rotation-capable key SET), namespaced `issuer*` Firestore collections, and a verifier that
// fetches THIS origin's `.well-known` cross-origin. SD-JWT VC only.
//
// PROOFING GATE: issuance is CLOSED by default (503 issuance_not_enabled) and only opens when
// ISSUER_OPEN_MINT=true. Phase 1 uses the open flag to prove the cross-origin trust path; Phase 2 replaces
// the flag with a real IDV proofing gate (a verified `idvSessions` doc) before any mint. See ../docs/issuer.md.
import { onRequest } from 'firebase-functions/v2/https';
import { defineSecret } from 'firebase-functions/params';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, Timestamp } from 'firebase-admin/firestore';
import { getAuth } from 'firebase-admin/auth';
import { randomBytes } from 'node:crypto';
import { verifyProofJwt } from './oid4vc.js';
import {
  loadKeySet,
  issuerWellKnown,
  credentialIssuerMetadata,
  authServerMetadata,
  mintAgeCredential,
  ageClaimsFromAge,
  MAX_BATCH,
} from './issuer.js';
import { makeIdv } from './idv/persona.js';

initializeApp();
const db = getFirestore();

// Distinct from the kunji-demo's `ISSUER_SIGNING_KEY`: Firebase Secrets are PROJECT-scoped and both codebases
// live in kunji-cc, so reusing that name would make the REAL issuer sign with the demo's (mints-to-anyone)
// key. This is the real issuer's own key (a rotation-capable set — see issuer.js loadKeySet).
const ISSUER_SIGNING_KEY = defineSecret('KUNJI_ISSUER_SIGNING_KEY');
// IDV vendor (Persona) — the age-proofing trust root. The webhook secret verifies a "verified" event
// genuinely came from Persona (a forged one would mint a false age credential). The inquiry template id is
// non-secret config (env PERSONA_INQUIRY_TEMPLATE_ID); env PERSONA_VERSION optionally pins the API version.
const PERSONA_API_KEY = defineSecret('PERSONA_API_KEY');
const PERSONA_WEBHOOK_SECRET = defineSecret('PERSONA_WEBHOOK_SECRET');
// The issuer's public origin — the `credential_issuer`/`iss` the wallet fetches + binds to, and the origin a
// verifier resolves keys from. Defaults to the Hosting `.web.app` URL so the cross-origin path works before
// the issuer.kunji.cc custom domain's DNS is live; flip to https://issuer.kunji.cc via env when DNS lands.
const ISSUER_ORIGIN = process.env.ISSUER_ORIGIN || 'https://issuer-kunji-cc.web.app';
// Issuance is closed unless explicitly opened. Production stays CLOSED until the Phase-2 IDV gate is wired;
// the open flag exists only to prove the Phase-1 cross-origin verify path with a real credential.
const OPEN_MINT = process.env.ISSUER_OPEN_MINT === 'true';

const VC_TTL_MS = 5 * 60 * 1000;
const IDV_TTL_MS = 15 * 60 * 1000; // a verified session lives long enough for the user to fetch the offer
const vcOpts = (secrets) => ({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30, secrets });
const ttlAfter = (ms) => Timestamp.fromMillis(Date.now() + ms + 5 * 60 * 1000);
const token = (n) => randomBytes(n).toString('base64url');
const keySet = () => loadKeySet(ISSUER_SIGNING_KEY.value());

// Reserve `n` contiguous StatusList indices (one per minted copy) in a transaction — the stateless,
// multi-instance fleet can't keep an in-memory counter. Namespaced `issuerStatusList` (NOT the demo's).
const allocStatusIdxs = async (n) => {
  const ref = db.collection('issuerStatusList').doc('age');
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const start = (snap.exists && snap.data().nextIdx) || 1;
    tx.set(ref, { nextIdx: start + n }, { merge: true });
    return Array.from({ length: n }, (_, i) => start + i);
  });
};
// StatusList check: a credential's idx is valid unless an admin has added it to `revoked` (Phase 3 revoke).
const checkStatus = async (idx) => {
  const snap = await db.collection('issuerStatusList').doc('age').get();
  const revoked = (snap.exists && snap.data().revoked) || [];
  return !revoked.includes(Number(idx)); // false ⇒ revoked
};

// Per-IP sliding-window rate limit on the public issuer endpoints (namespaced `issuerRateLimits`).
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

// ── IDV proofing gate (Persona) — verify age once, then allow ONE credential offer ──
// The vendor holds the document/biometric + liability; we receive only a verified age, store the derived
// `age_over_N` booleans + the vendor session id (audit), and NEVER persist the DOB. The adapter
// (idv/persona.js) keeps a vendor-neutral interface so the provider stays swappable. See docs/issuer.md.
const PERSONA_VERSION = process.env.PERSONA_VERSION;
const PERSONA_TEMPLATE_ID = process.env.PERSONA_INQUIRY_TEMPLATE_ID;

// POST /idv/start → create a hosted verification session; the page stashes `sid` + redirects to `url`.
// Rate-limited (each session may bill).
export const issuerIdvStart = onRequest(vcOpts([PERSONA_API_KEY]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  if (await rateLimited(req.ip, 10)) return res.status(429).json({ error: 'rate_limited' });
  try {
    const idv = makeIdv({ apiKey: PERSONA_API_KEY.value(), templateId: PERSONA_TEMPLATE_ID, version: PERSONA_VERSION });
    const sid = token(24);
    const { vendorSessionId, url } = await idv.createSession({ returnUrl: `${ISSUER_ORIGIN}/`, sid });
    await db.collection('idvSessions').doc(sid).set({ status: 'pending', vendorSessionId, ttl: ttlAfter(IDV_TTL_MS) });
    res.json({ sid, url });
  } catch {
    res.status(502).json({ error: 'idv_start_failed' });
  }
});

// POST /idv/webhook ← Persona. The adapter verifies the signature over the RAW body (THE critical control)
// and normalizes the event to { ok, status, sid, vendorSessionId }. On `verified` we retrieve the inquiry
// fresh (authoritative age), derive the boolean thresholds, and record ONLY those + the vendor session id —
// the DOB is never written. Idempotent (the vendor retries); minting is separately single-use at /credential.
export const issuerIdvWebhook = onRequest(
  { cors: false, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30, secrets: [PERSONA_API_KEY, PERSONA_WEBHOOK_SECRET] },
  async (req, res) => {
    if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
    const idv = makeIdv({
      apiKey: PERSONA_API_KEY.value(),
      webhookSecret: PERSONA_WEBHOOK_SECRET.value(),
      version: PERSONA_VERSION,
    });
    const evt = idv.parseWebhook({ rawBody: req.rawBody, headers: req.headers });
    if (!evt.ok) return res.status(400).json({ error: 'bad_signature' }); // forged/misconfigured — never trust it
    try {
      if (evt.status === 'ignore' || !evt.sid) return res.json({ ok: true }); // irrelevant/not ours — ack
      const ref = db.collection('idvSessions').doc(String(evt.sid));
      if (evt.status === 'verified') {
        const r = await idv.verifiedAgeFor(evt.vendorSessionId); // fresh authenticated retrieve (dob → age, in memory)
        await db.runTransaction(async (tx) => {
          const snap = await tx.get(ref);
          if (!snap.exists) return; // already consumed/expired — a re-delivered event must never resurrect it
          if (!r.ok) tx.update(ref, { status: 'failed', ttl: ttlAfter(IDV_TTL_MS) });
          else tx.update(ref, { status: 'verified', claims: ageClaimsFromAge(r.age), vendorRef: evt.vendorSessionId, ttl: ttlAfter(IDV_TTL_MS) });
        });
      } else if (evt.status === 'failed') {
        await db.runTransaction(async (tx) => {
          const snap = await tx.get(ref);
          // only a still-pending session regresses to failed — never clobber a verified/consumed one (out-of-order delivery)
          if (snap.exists && snap.data().status === 'pending') tx.update(ref, { status: 'failed', ttl: ttlAfter(IDV_TTL_MS) });
        });
      }
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'webhook_processing_failed' }); // let the vendor retry (don't drop a verification)
    }
  },
);

// GET /idv/status?sid= → the issuer page polls this; returns only the non-privileged status.
export const issuerIdvStatus = onRequest(vcOpts([]), async (req, res) => {
  const snap = await db.collection('idvSessions').doc(String(req.query.sid || '')).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_session' });
  res.json({ status: snap.data().status || 'pending' });
});

// ── Issuer metadata + trust anchor (the key SET a verifier fetches cross-origin) ──
export const issuerOidcMetadata = onRequest(vcOpts([]), (_req, res) => res.json(credentialIssuerMetadata(ISSUER_ORIGIN)));
export const issuerOauthMetadata = onRequest(vcOpts([]), (_req, res) => res.json(authServerMetadata(ISSUER_ORIGIN)));
export const issuerKeys = onRequest(vcOpts([ISSUER_SIGNING_KEY]), (_req, res) =>
  res.json(issuerWellKnown(ISSUER_ORIGIN, keySet())),
);

// ── OpenID4VCI: offer → token → credential ──
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

// GET /credential-offer → mint a single-use pre-authorized_code + return the offer.
// PROOFING GATE: with `?sid=<verified IDV session>` → mint bound to that session's verified age booleans and
// CONSUME the session (one proofing ⇒ one offer/batch). Without a sid only the OPEN_MINT test path (default
// claims) is allowed; otherwise closed (503) until proofing is enabled.
export const issuerOffer = onRequest(vcOpts([]), async (req, res) => {
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  const sid = String(req.query.sid || '');
  let claims = null;
  let vendorRef = null;
  if (sid) {
    const verified = await db.runTransaction(async (tx) => {
      const ref = db.collection('idvSessions').doc(sid);
      const snap = await tx.get(ref);
      const d = snap.exists ? snap.data() : null;
      if (!d || d.status !== 'verified') return null;
      tx.delete(ref); // consume: one verified proofing ⇒ one offer
      return d;
    });
    if (!verified) return res.status(403).json({ error: 'not_verified' });
    claims = verified.claims || null;
    vendorRef = verified.vendorRef || null;
  } else if (!OPEN_MINT) {
    return res.status(503).json({ error: 'issuance_not_enabled' });
  }
  const code = token(24);
  await db.collection('issuerOffers').doc(code).set({ configurationId: 'age', claims, vendorRef, ttl: ttlAfter(VC_TTL_MS) });
  const offer = {
    credential_issuer: ISSUER_ORIGIN,
    credential_configuration_ids: ['age'],
    grants: { [PRE_AUTH_GRANT]: { 'pre-authorized_code': code } },
  };
  res.json({ offer, offerUri: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}` });
});

// POST /token → redeem the pre-authorized_code (single-use) for an access_token + c_nonce (bearer).
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
  // Carry the verified age claims + vendor ref from the offer onto the token, so /credential mints exactly
  // what the IDV gate proved (issuerCredentialEndpoint reads consumed.claims / consumed.vendorRef).
  await db
    .collection('issuerTokens')
    .doc(access_token)
    .set({ cNonce, claims: offer.claims || null, vendorRef: offer.vendorRef || null, ttl: ttlAfter(VC_TTL_MS) });
  res.json({ access_token, token_type: 'bearer', expires_in: 300, c_nonce: cNonce, c_nonce_expires_in: 300 });
});

// POST /credential → verify the holder proof JWT(s) (single-use token) and mint the SD-JWT VC(s).
// Writes a data-minimized ledger row per copy (the age booleans + idx + kid — NEVER a DOB/document).
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
  const fmt = req.body?.format;
  if (fmt && fmt !== 'vc+sd-jwt' && fmt !== 'dc+sd-jwt') return res.status(400).json({ error: 'unsupported_credential_format' });
  const typ = fmt === 'dc+sd-jwt' ? fmt : undefined;
  const ks = keySet();
  // The verified-age claims to bake. Phase 1 (open mint) uses the demo default; Phase 2 reads the booleans
  // the IDV gate stored on the token's session.
  const claims = consumed.claims || undefined;

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
  const idxs = await allocStatusIdxs(holderJwks.length);
  const creds = holderJwks.map((holderJwk, i) => mintAgeCredential({ keySet: ks, origin: ISSUER_ORIGIN, holderJwk, idx: idxs[i], claims, typ }));
  // Data-minimized issuance ledger (admin console reads it; no PII — booleans + idx + kid + vendor ref only).
  const issuedAt = Date.now();
  await Promise.all(
    idxs.map((idx) =>
      db.collection('issuerCredentials').doc(`age_${idx}`).set({
        vct: 'age',
        idx,
        kid: ks.active.kid,
        claims: claims || null,
        vendorRef: consumed.vendorRef || null,
        issuedAt,
      }),
    ),
  );
  res.json(Array.isArray(batch) && batch.length ? { credentials: creds } : { credential: creds[0] });
});

// GET /status/1?idx= → StatusList check (a verifier's checkStatus honors valid:false as revoked).
export const issuerStatusEndpoint = onRequest(vcOpts([]), async (req, res) => {
  res.json({ valid: await checkStatus(req.query.idx) });
});

// ── Admin console API (admin.kunji.cc) — operator-only: ledger, revocation, stats ──
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

// Issuance ledger, newest first, paginated by the (unique, sequential) StatusList idx. No PII — the rows are
// booleans + idx + kid + vendorRef + issuedAt; each is flagged with its current revocation status.
const adminLedger = async (req) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const before = Number(req.query.before);
  let q = db.collection('issuerCredentials').orderBy('idx', 'desc');
  if (Number.isInteger(before) && before > 0) q = q.where('idx', '<', before).orderBy('idx', 'desc');
  const [snap, statusSnap] = await Promise.all([
    q.limit(limit).get(),
    db.collection('issuerStatusList').doc('age').get(),
  ]);
  const revoked = new Set(((statusSnap.exists && statusSnap.data().revoked) || []).map(Number));
  const items = snap.docs.map((d) => {
    const x = d.data();
    return { idx: x.idx, vct: x.vct, kid: x.kid, claims: x.claims || null, vendorRef: x.vendorRef || null, issuedAt: x.issuedAt || null, revoked: revoked.has(Number(x.idx)) };
  });
  return { items, nextBefore: items.length === limit ? items[items.length - 1].idx : null };
};

// Aggregate stats (count() — no docs returned): the IDV funnel + issuance/revocation totals.
const adminStats = async () => {
  const idv = db.collection('idvSessions');
  const [pending, verified, failed, issued, statusSnap] = await Promise.all([
    idv.where('status', '==', 'pending').count().get(),
    idv.where('status', '==', 'verified').count().get(),
    idv.where('status', '==', 'failed').count().get(),
    db.collection('issuerCredentials').count().get(),
    db.collection('issuerStatusList').doc('age').get(),
  ]);
  const revoked = ((statusSnap.exists && statusSnap.data().revoked) || []).length;
  return {
    idv: { pending: pending.data().count, verified: verified.data().count, failed: failed.data().count },
    issued: issued.data().count,
    revoked,
  };
};

// Revoke / un-revoke an idx by toggling it in issuerStatusList/age.revoked (transaction; idempotent).
const adminSetRevoked = async (idx, revoke) => {
  const n = Number(idx);
  if (!Number.isInteger(n) || n < 1) throw new Error('bad_idx');
  const ref = db.collection('issuerStatusList').doc('age');
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const cur = new Set(((snap.exists && snap.data().revoked) || []).map(Number));
    if (revoke) cur.add(n);
    else cur.delete(n);
    tx.set(ref, { revoked: Array.from(cur) }, { merge: true });
  });
  return { idx: n, revoked: revoke };
};

// /api/** (admin.kunji.cc rewrite) — one Function, internal path router; same-origin (no CORS).
export const issuerAdminApi = onRequest({ cors: false, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  const admin = await requireAdmin(req);
  if (!admin) return res.status(401).json({ error: 'unauthorized' });
  try {
    if (req.method === 'GET' && req.path === '/api/ledger') return res.json(await adminLedger(req));
    if (req.method === 'GET' && req.path === '/api/stats') return res.json(await adminStats());
    if (req.method === 'POST' && req.path === '/api/revoke') return res.json(await adminSetRevoked(req.body?.idx, true));
    if (req.method === 'POST' && req.path === '/api/unrevoke') return res.json(await adminSetRevoked(req.body?.idx, false));
    return res.status(404).json({ error: 'not_found' });
  } catch (e) {
    return res.status(e?.message === 'bad_idx' ? 400 : 500).json({ error: e?.message === 'bad_idx' ? 'bad_idx' : 'admin_failed' });
  }
});
