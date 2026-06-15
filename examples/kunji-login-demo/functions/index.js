import { onRequest } from 'firebase-functions/v2/https';
import { defineSecret } from 'firebase-functions/params';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, Timestamp } from 'firebase-admin/firestore';
import { randomBytes } from 'node:crypto';
import { verifyAssertion } from './verify.js';
import { verifyCapabilityAssertion } from './capability.js';
import { verifyCredentialPresentation, parseVcScope } from './vc.js';
import { verifyBbsPresentation, isBbsPresentation, decodeBbsPresentation } from './vcBbs.js';
import { b64uToBytes } from './bbs.js';
import { verifyProofJwt } from './oid4vc.js';
import { issuerKey, issuerWellKnown, credentialIssuerMetadata, authServerMetadata, mintAgeCredential, MAX_BATCH } from './issuer.js';
import { verifierKey, verifierWellKnown, buildVpRequest, verifyVp } from './verifier.js';

initializeApp();
const db = getFirestore();
const SESSION_TTL_MS = 2 * 60 * 1000;

// ── Live verified-credentials demo (OpenID4VCI issuer + OpenID4VP verifier) ──────────────────────────
// The signing keys live as Firebase Secrets (Cloud Functions FS is read-only) — generate locally and
// `firebase functions:secrets:set ISSUER_SIGNING_KEY` / `VERIFIER_SIGNING_KEY` (base64 Ed25519 secret key).
const ISSUER_SIGNING_KEY = defineSecret('ISSUER_SIGNING_KEY');
const VERIFIER_SIGNING_KEY = defineSecret('VERIFIER_SIGNING_KEY');
// The demo's public origin — the `credential_issuer`/`iss`/`client_id` the wallet fetches + binds to. Must
// be the live host (override via DEMO_ORIGIN env for the emulator). The wallet rejects a non-https issuer.
const DEMO_ORIGIN = process.env.DEMO_ORIGIN || 'https://kunji-demo.web.app';
const VC_TTL_MS = 5 * 60 * 1000;
const vcOpts = (secrets) => ({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30, secrets });
const ttlAfter = (ms) => Timestamp.fromMillis(Date.now() + ms + 5 * 60 * 1000);

// Reserve `n` contiguous StatusList indices (one per minted copy) in a transaction — the in-memory
// counter of the reference issuer can't survive a stateless multi-instance fleet.
const allocStatusIdxs = async (n) => {
  const ref = db.collection('statusList').doc('age');
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const start = (snap.exists && snap.data().nextIdx) || 1;
    tx.set(ref, { nextIdx: start + n }, { merge: true });
    return Array.from({ length: n }, (_, i) => start + i);
  });
};
// Local trust-anchor resolution for the verifier: the credential's `iss` IS this same demo, so resolve the
// issuer keys + StatusList locally (no self-fetch). getIssuerKeys/checkStatus shapes match verifyVpToken.
const localIssuerKeys = (iss) => (iss === DEMO_ORIGIN ? issuerWellKnown(DEMO_ORIGIN, issuerKey(ISSUER_SIGNING_KEY.value()).publicKey).keys : []);
const localCheckStatus = async (_uri, idx) => {
  const snap = await db.collection('statusList').doc('age').get();
  const revoked = (snap.exists && snap.data().revoked) || [];
  return !revoked.includes(Number(idx)); // false ⇒ revoked
};
// Short, url-safe session id / challenge (base64url is ~30% shorter than hex → leaner QR;
// same entropy). They're opaque tokens the wallet only echoes back, and `-_` are valid
// Firestore doc-ids.
const token = (n) => randomBytes(n).toString('base64url');
const sessionRef = (id) => db.collection('loginSessions').doc(id);

// Verified credentials (optional): if an assertion presents one, verify it LOCALLY against the
// issuer's own keys + StatusList — no kunji server. Set REQUIRE_VC (e.g. "vc:age#age_over_18") to
// REQUIRE a passing predicate. A production RP caches/pins issuer keys + guards the fetch (SSRF).
const REQUIRE_VC = process.env.REQUIRE_VC || null;
const fetchIssuerKeys = async (iss) => {
  const r = await fetch(`${iss}/.well-known/kunji-issuer.json`);
  if (!r.ok) throw new Error('issuer_unreachable');
  return (await r.json()).keys || [];
};
const fetchStatus = async (uri, idx) => {
  const r = await fetch(`${uri}?idx=${encodeURIComponent(idx)}`);
  if (!r.ok) throw new Error('status_unreachable');
  return (await r.json()).valid !== false; // false ⇒ revoked
};
// The issuer's BBS public key (the `alg:'BBS'` .well-known entry) — for v3 unlinkable presentations.
const fetchIssuerBbsKey = async (iss) => {
  const k = (await fetchIssuerKeys(iss)).find((x) => x.alg === 'BBS' && x.pub);
  if (!k) throw new Error('issuer_bbs_key_not_found');
  return b64uToBytes(k.pub);
};

// A globally-unique 6-digit code (equality-only query → no composite index needed).
const freshCode = async () => {
  for (let i = 0; i < 8; i++) {
    const code = String(Math.floor(100000 + (randomBytes(4).readUInt32BE(0) % 900000)));
    const dup = await db.collection('loginSessions').where('code', '==', code).limit(1).get();
    if (dup.empty) return code;
  }
  throw new Error('code_alloc_failed');
};

// Per-IP sliding-window rate limit (protects the 6-digit code space + the demo issuer/verifier endpoints).
const rateLimited = async (ip, max = 10, windowMs = 60 * 1000, prefix = 'lookup') => {
  const ref = db
    .collection('rateLimits')
    .doc(`${prefix}_${(ip || 'unknown').replace(/[^\w.:-]/g, '_')}`);
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

// Global cap on FAILED code lookups — defense-in-depth against distributed code
// brute-force (per-IP limiting is XFF-spoofable). Only failures count, so legitimate
// valid-code lookups never trip it.
const GLOBAL_FAIL_REF = () => db.collection('rateLimits').doc('global_code_failures');
const globalFailuresExceeded = async (max = 60, windowMs = 60 * 1000) => {
  const snap = await GLOBAL_FAIL_REF().get();
  const d = snap.exists ? snap.data() : null;
  return !!d && Date.now() - d.start <= windowMs && d.count >= max;
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
export const createSession = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const { audience, callbackUrl } = req.body || {};
  if (!audience || !callbackUrl)
    return res.status(400).json({ error: 'audience and callbackUrl required' });

  const sessionId = token(16);
  const challenge = token(32);
  const code = await freshCode();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  // `ttl` lets Firestore's TTL policy auto-delete the doc ~5 min after expiry,
  // so loginSessions never grows unbounded.
  const ttl = Timestamp.fromMillis(expiresAt + 5 * 60 * 1000);
  await sessionRef(sessionId).set({
    challenge,
    audience,
    callbackUrl,
    code,
    status: 'pending',
    sub: null,
    expiresAt,
    ttl,
  });
  res.json({ sessionId, challenge, code, expiresAt });
});

// Device-authorization: kunji resolves a 6-digit code to the pending session so it
// can sign the challenge. Returns the challenge/callback (NOT an approval).
export const lookupSession = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  if (await globalFailuresExceeded()) return res.status(429).json({ error: 'rate_limited' });

  const code = String(req.query.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'bad_code' });

  const q = await db.collection('loginSessions').where('code', '==', code).limit(1).get();
  const doc = q.docs[0];
  const s = doc?.data();
  if (!doc || s.status !== 'pending') {
    await bumpGlobalFailure();
    return res.status(404).json({ error: 'invalid_code' });
  }
  if (Date.now() > s.expiresAt) return res.status(410).json({ error: 'expired_code' });

  res.json({
    sessionId: doc.id,
    challenge: s.challenge,
    audience: s.audience,
    callbackUrl: s.callbackUrl,
    expiresAt: s.expiresAt,
  });
});

// Poll endpoint for the drop-in widget (rp.js): resolve a sessionId to its status.
// Read-only; the doc holds no secrets (just status + the per-app sub).
export const getSessionStatus = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  const sessionId = String(req.query.sessionId || '');
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  const snap = await sessionRef(sessionId).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_session' });
  const s = snap.data();
  // `claims` is the optional, self-asserted profile the user chose to share (or null).
  res.json({ status: s.status, sub: s.sub || null, claims: s.claims || null, verified: s.verified || null });
});

// The wallet POSTs the signed assertion here (spec §5.2). Full §6 verification.
export const kunjiCallback = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const assertion = req.body || {};
  const sessionId = assertion?.signedPayload?.sessionId;
  if (!sessionId) return res.status(400).json({ error: 'malformed_assertion' });
  const ref = sessionRef(sessionId);

  try {
    // Verify any presented verified credentials BEFORE the consume transaction — issuer-key +
    // StatusList lookups need network fetches, which can't run inside a Firestore transaction. The
    // session's challenge/audience are immutable once created, so this pre-read is safe; the tx below
    // still atomically re-verifies the §6 assertion + consumes the session.
    let verified = null;
    const presentations = assertion?.signedPayload?.vc_presentations;
    if (Array.isArray(presentations) && presentations.length) {
      const pre = await ref.get();
      const session = pre.exists ? pre.data() : null;
      if (!session) return res.status(400).json({ error: 'unknown_session' });
      verified = [];
      for (const presentation of presentations) {
        // Dispatch by format: a `bbs~`-tagged entry is an unlinkable BBS proof (v3); else SD-JWT.
        const vr = isBbsPresentation(presentation)
          ? await verifyBbsPresentation({
              presentation: decodeBbsPresentation(presentation),
              getIssuerBbsKey: fetchIssuerBbsKey,
              audience: session.audience,
              nonce: session.challenge,
            })
          : await verifyCredentialPresentation({
              presentation,
              audience: session.audience,
              nonce: session.challenge,
              getIssuerKeys: fetchIssuerKeys,
              checkStatus: fetchStatus,
            });
        if (!vr.ok) return res.status(400).json({ error: 'vc_' + vr.error });
        verified.push({ iss: vr.iss, vct: vr.vct, claims: vr.claims });
      }
    }
    if (REQUIRE_VC) {
      const want = parseVcScope(REQUIRE_VC);
      const ok = (verified || []).some(
        (v) => v.vct === want.vct && (!want.iss || v.iss === want.iss) && want.disclose.every((c) => v.claims?.[c] === true),
      );
      if (!ok) return res.status(400).json({ error: 'vc_predicate_failed' });
    }

    // Verify + consume atomically so a captured/duplicated assertion can't approve
    // the same session twice (single-use, spec §6.7).
    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const session = snap.exists ? snap.data() : null;
      const r = verifyAssertion({ assertion, session, audience: session?.audience });
      if (!r.ok) return r;
      if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
      tx.update(ref, { status: 'approved', sub: r.sub, claims: r.claims || null, verified });
      return r;
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ error: 'callback_failed' });
  }
});

// Agentic delegation: an AGENT presents a capability (minted by the user's wallet) + a
// holder-of-key proof for this session's challenge. Verified locally like §6, but the
// principal acts via a scoped, expiring, revocable capability instead of a fresh approval.
// See docs/agentic-delegation.md.
export const kunjiAgent = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const { sessionId, capability, agentProof } = req.body || {};
  if (!sessionId || !capability || !agentProof) return res.status(400).json({ error: 'malformed_request' });
  const ref = sessionRef(sessionId);

  try {
    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const session = snap.exists ? snap.data() : null;
      if (!session) return { ok: false, error: 'unknown_session' };
      if (Date.now() > session.expiresAt) return { ok: false, error: 'session_expired' };
      const r = await verifyCapabilityAssertion({
        capability,
        agentProof,
        audience: session.audience,
        challenge: session.challenge,
        // Read the denylist THROUGH the transaction so a concurrent revocation joins the
        // read set (forces a retry) — no TOCTOU between the check and the approve.
        isRevoked: async (jti) =>
          (await tx.get(db.collection('revokedCapabilities').doc(String(jti)))).exists,
        // kunji-hosted, issuer-signed revocations — the user revoking from their wallet. The
        // verifier only honors it if the signature checks out against the capability's own key.
        getRevocation: async (jti) => {
          const d = await tx.get(db.collection('revocations').doc(String(jti)));
          return d.exists ? d.data() : null;
        },
      });
      if (!r.ok) return r;
      if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
      tx.update(ref, { status: 'approved', sub: r.sub, scope: r.scope, agent: true });
      return r;
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({ status: 'ok' });
  } catch {
    res.status(500).json({ error: 'agent_failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// Live verified-credentials demo — OpenID4VCI issuance + OpenID4VP presentation against the real wallet.
// DEMO ONLY: the issuer mints `age_over_18` to anyone (rate-limited); a real issuer authenticates the
// subject first. SD-JWT + pre-authorized_code + DCQL + cleartext direct_post (the first cut).
// ════════════════════════════════════════════════════════════════════════════════════════════════════

// ── Issuer metadata + trust anchor ──
export const issuerMetadata = onRequest(vcOpts([]), (_req, res) => res.json(credentialIssuerMetadata(DEMO_ORIGIN)));
export const oauthMetadata = onRequest(vcOpts([]), (_req, res) => res.json(authServerMetadata(DEMO_ORIGIN)));
export const issuerWellKnownFn = onRequest(vcOpts([ISSUER_SIGNING_KEY]), (_req, res) =>
  res.json(issuerWellKnown(DEMO_ORIGIN, issuerKey(ISSUER_SIGNING_KEY.value()).publicKey)),
);

// ── OpenID4VCI: offer → token → credential ──
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

// GET /credential-offer → mint a single-use pre-authorized_code + return the offer (+ openid-credential-offer:// URI).
export const credentialOffer = onRequest(vcOpts([]), async (req, res) => {
  if (await rateLimited(req.ip, 30, 60 * 1000, 'vci')) return res.status(429).json({ error: 'rate_limited' });
  const code = token(24);
  await db.collection('oid4vciOffers').doc(code).set({ configurationId: 'age', ttl: ttlAfter(VC_TTL_MS) });
  const offer = {
    credential_issuer: DEMO_ORIGIN,
    credential_configuration_ids: ['age'],
    grants: { [PRE_AUTH_GRANT]: { 'pre-authorized_code': code } },
  };
  res.json({ offer, offerUri: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}` });
});

// POST /token → redeem the pre-authorized_code (single-use) for an access_token + c_nonce (bearer).
export const issuerToken = onRequest(vcOpts([]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  if (await rateLimited(req.ip, 30, 60 * 1000, 'vci')) return res.status(429).json({ error: 'rate_limited' });
  if (req.body?.grant_type !== PRE_AUTH_GRANT) return res.status(400).json({ error: 'unsupported_grant_type' });
  const code = req.body['pre-authorized_code'];
  const ok = await db.runTransaction(async (tx) => {
    const ref = db.collection('oid4vciOffers').doc(String(code || ''));
    const snap = await tx.get(ref);
    if (!snap.exists) return false;
    tx.delete(ref); // single-use
    return true;
  });
  if (!ok) return res.status(400).json({ error: 'invalid_grant' });
  const access_token = token(24);
  const cNonce = token(24);
  await db.collection('oid4vciTokens').doc(access_token).set({ cNonce, ttl: ttlAfter(VC_TTL_MS) });
  res.json({ access_token, token_type: 'bearer', expires_in: 300, c_nonce: cNonce, c_nonce_expires_in: 300 });
});

// POST /credential → verify the holder proof JWT(s) (single-use token) and mint the SD-JWT VC(s).
export const issuerCredential = onRequest(vcOpts([ISSUER_SIGNING_KEY]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const tok = /^(?:DPoP|Bearer) (.+)$/.exec(String(req.headers.authorization || ''))?.[1];
  const consumed = await db.runTransaction(async (tx) => {
    const ref = db.collection('oid4vciTokens').doc(String(tok || ''));
    const snap = await tx.get(ref);
    if (!snap.exists) return null;
    tx.delete(ref); // single-use
    return snap.data();
  });
  if (!consumed) return res.status(401).json({ error: 'invalid_token' });
  const fmt = req.body?.format;
  if (fmt && fmt !== 'vc+sd-jwt' && fmt !== 'dc+sd-jwt') return res.status(400).json({ error: 'unsupported_credential_format' });
  const typ = fmt === 'dc+sd-jwt' ? fmt : undefined;
  const { secretKey } = issuerKey(ISSUER_SIGNING_KEY.value());

  // Batch (unlinkability v2): one one-time copy per holder key. `proof` is the pre-batch fallback.
  const batch = req.body?.proofs?.jwt;
  const proofs = Array.isArray(batch) && batch.length ? batch : req.body?.proof?.jwt ? [req.body.proof.jwt] : [];
  if (!proofs.length) return res.status(400).json({ error: 'invalid_proof' });
  if (proofs.length > MAX_BATCH) return res.status(400).json({ error: 'batch_too_large', max: MAX_BATCH });
  const holderJwks = [];
  for (const jwt of proofs) {
    const v = verifyProofJwt({ proofJwt: jwt, audience: DEMO_ORIGIN, cNonce: consumed.cNonce });
    if (!v.ok) return res.status(400).json({ error: 'invalid_proof', detail: v.error });
    holderJwks.push(v.holderJwk);
  }
  const idxs = await allocStatusIdxs(holderJwks.length);
  const creds = holderJwks.map((holderJwk, i) => mintAgeCredential({ secretKey, origin: DEMO_ORIGIN, holderJwk, idx: idxs[i], typ }));
  res.json(Array.isArray(batch) && batch.length ? { credentials: creds } : { credential: creds[0] });
});

// GET /status/1?idx= → StatusList check (the RP's checkStatus honors valid:false as revoked).
export const issuerStatus = onRequest(vcOpts([]), async (req, res) => {
  res.json({ valid: await localCheckStatus(null, req.query.idx) });
});

// ── OpenID4VP: signed request → present → result ──
export const verifierWellKnownFn = onRequest(vcOpts([VERIFIER_SIGNING_KEY]), (_req, res) =>
  res.json(verifierWellKnown(DEMO_ORIGIN, verifierKey(VERIFIER_SIGNING_KEY.value()).publicKey)),
);

// GET /oid4vp/request → a signed JAR asking for age_over_18 (DCQL) + a state to poll.
export const oid4vpRequest = onRequest(vcOpts([VERIFIER_SIGNING_KEY]), async (req, res) => {
  if (await rateLimited(req.ip, 30, 60 * 1000, 'vci')) return res.status(429).json({ error: 'rate_limited' });
  const state = token(16);
  const nonce = token(24);
  const { secretKey } = verifierKey(VERIFIER_SIGNING_KEY.value());
  const { requestUri, dcqlQuery } = buildVpRequest({ secretKey, clientId: DEMO_ORIGIN, base: DEMO_ORIGIN, state, nonce });
  await db.collection('oid4vpRequests').doc(state).set({ nonce, dcqlQuery, approved: null, claims: null, ttl: ttlAfter(VC_TTL_MS) });
  res.json({ state, requestUri });
});

// POST /oid4vp/response ← { vp_token, state } — the wallet's direct_post. Verify + record the result.
export const oid4vpResponse = onRequest(vcOpts([ISSUER_SIGNING_KEY]), async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const { vp_token, state } = req.body || {};
  const ref = db.collection('oid4vpRequests').doc(String(state || ''));
  const snap = await ref.get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_state' });
  const rec = snap.data();
  const r = await verifyVp({
    vpToken: vp_token,
    dcqlQuery: rec.dcqlQuery,
    clientId: DEMO_ORIGIN,
    nonce: rec.nonce,
    getIssuerKeys: async (iss) => localIssuerKeys(iss),
    checkStatus: localCheckStatus,
  });
  if (!r.ok) return res.status(400).json({ error: r.error });
  await ref.update({ approved: true, claims: r.claims });
  res.json({ status: 'approved', claims: r.claims });
});

// GET /oid4vp/result?state= → the demo page polls this until the wallet has presented.
export const oid4vpResult = onRequest(vcOpts([]), async (req, res) => {
  const snap = await db.collection('oid4vpRequests').doc(String(req.query.state || '')).get();
  if (!snap.exists) return res.status(404).json({ error: 'unknown_state' });
  const s = snap.data();
  res.json({ approved: s.approved === true, claims: s.claims || null });
});
