// Signed vault writes. Clients can READ vaults/{vaultId} directly (gated by the
// secret, master-key-derived vaultId), but WRITES are denied by rules and must go
// through this function with an Ed25519 signature from the vault write key (also
// master-key-derived). The function never sees the master key or plaintext — only the
// vault PUBLIC key, signatures, and already-encrypted app blobs.
import { onRequest } from 'firebase-functions/v2/https';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, FieldValue, Timestamp } from 'firebase-admin/firestore';
import { ed25519 } from '@noble/curves/ed25519.js';

initializeApp();
const db = getFirestore();

// Canonical JSON (sorted keys, no whitespace) — MUST match the client signer.
const canonicalJson = (o) =>
  o === null || typeof o !== 'object' || Array.isArray(o)
    ? JSON.stringify(o)
    : JSON.stringify(
        Object.fromEntries(
          Object.keys(o)
            .sort()
            .map((k) => [k, o[k]]),
        ),
      );

const b64 = (s) => Buffer.from(s, 'base64');
const HEX64 = /^[0-9a-f]{64}$/i; // vaultId is the 64-hex master-key-derived id
const SAFE_ID = /^[A-Za-z0-9_-]{1,200}$/; // a Firestore-doc-id-safe appId (64-hex for new
// apps; legacy apps may have random ~20-char ids)
const MAX_DOC_BYTES = 16 * 1024;
const MAX_PROFILE_BYTES = 64 * 1024; // profile may carry a small encrypted avatar

// `maxInstances` caps 2nd-gen scale so a flood can't run up compute/spend without bound;
// the caps leave ample headroom for real traffic. Scale-to-zero kept (no minInstances).
export const vaultWrite = onRequest({ cors: true, maxInstances: 10, memory: '256MiB', timeoutSeconds: 30 }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const {
    vaultId,
    op,
    appId,
    kind,
    doc: docPayload,
    publicKey,
    signedToken,
    timestamp,
  } = req.body || {};

  // `kind` selects the target collection: undefined/'app' → apps/{appId} (back-compat,
  // existing clients omit it), 'profile' → profile/self (the user's custom profile),
  // 'activity' → activity/{appId} (append-only, encrypted, shared-across-devices log),
  // 'agent' → agents/{appId} (encrypted authorized-agent metadata; appId = capability jti),
  // 'device' → devices/{appId} (encrypted linked-device metadata; appId = per-device id).
  const isProfile = kind === 'profile';
  const isActivity = kind === 'activity';
  const isAgent = kind === 'agent';
  const isDevice = kind === 'device';

  // 1. shape
  if (
    !HEX64.test(vaultId || '') ||
    !SAFE_ID.test(appId || '') ||
    (kind !== undefined && !['app', 'profile', 'activity', 'agent', 'device'].includes(kind)) ||
    (op !== 'set' && op !== 'delete') ||
    !publicKey ||
    !signedToken ||
    typeof timestamp !== 'number'
  ) {
    return res.status(400).json({ error: 'bad_request' });
  }
  if (Math.abs(Date.now() - timestamp) > 120_000) return res.status(400).json({ error: 'stale' });
  if (op === 'set') {
    if (!docPayload || typeof docPayload !== 'object' || Array.isArray(docPayload))
      return res.status(400).json({ error: 'bad_doc' });
    if (Buffer.byteLength(JSON.stringify(docPayload)) > (isProfile ? MAX_PROFILE_BYTES : MAX_DOC_BYTES))
      return res.status(400).json({ error: 'too_large' });
  }

  // 2. signature over the canonical request (excludes signedToken). `kind` is included
  // only when sent, so legacy app writes (no kind) stay byte-identical and an attacker
  // cannot re-target a captured write by flipping kind.
  const payload = { appId, doc: docPayload ?? null, op, publicKey, timestamp, vaultId };
  if (kind !== undefined) payload.kind = kind;
  let sigOk = false;
  try {
    sigOk = ed25519.verify(
      b64(signedToken),
      new TextEncoder().encode(canonicalJson(payload)),
      b64(publicKey),
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) return res.status(401).json({ error: 'bad_signature' });

  // 3. TOFU-bound write via Admin
  const vaultRef = db.collection('vaults').doc(vaultId);
  const targetRef = isProfile
    ? vaultRef.collection('profile').doc('self')
    : isActivity
      ? vaultRef.collection('activity').doc(appId)
      : isAgent
        ? vaultRef.collection('agents').doc(appId)
        : isDevice
          ? vaultRef.collection('devices').doc(appId)
          : vaultRef.collection('apps').doc(appId);
  // Activity entries self-prune via a Firestore TTL policy on `expiresAt` (a non-sensitive
  // timestamp; the payload itself stays encrypted). 90 days.
  const ACTIVITY_TTL_MS = 90 * 24 * 60 * 60 * 1000;
  try {
    await db.runTransaction(async (tx) => {
      const meta = await tx.get(vaultRef);
      const existing = op === 'set' ? await tx.get(targetRef) : null;

      const registered = meta.exists ? meta.data().writePublicKey : null;
      if (!registered)
        tx.set(vaultRef, { writePublicKey: publicKey }, { merge: true }); // first-write-wins
      else if (registered !== publicKey) throw new Error('not_authorized');

      if (op === 'delete') {
        tx.delete(targetRef);
      } else {
        // Preserve the original createdAt on re-writes.
        const createdAt = existing?.exists
          ? existing.data().createdAt
          : FieldValue.serverTimestamp();
        const extra = isActivity
          ? { expiresAt: Timestamp.fromMillis(Date.now() + ACTIVITY_TTL_MS) }
          : {};
        tx.set(targetRef, { ...docPayload, createdAt, ...extra });
      }
    });
  } catch (e) {
    if (e?.message === 'not_authorized') return res.status(403).json({ error: 'not_authorized' });
    return res.status(500).json({ error: 'write_failed' });
  }

  // Echo the caller IP (the TCP peer — we see it inherently). The activity client encrypts it
  // into the entry client-side; the function NEVER persists it. Harmless for app/profile writes.
  res.json({ status: 'ok', ip: req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || null });
});

// ── Device-link code lookup ──────────────────────────────────────────────────
// Resolves a short numeric link code (shown by the issuing device) to that device's
// link session {linkId, pubA}, so the new device can join without scanning a QR. The
// code is short, so this is rate-limited (per-IP + a global failed-lookup cap) to bound
// enumeration; a guessed code only yields a public key, and the shared-secret SAS the
// user confirms on both screens is what actually prevents the master key reaching a
// wrong device. linkSessions are written client-side under firestore.rules; this
// function only READS them (Admin SDK), never the master key.
const CODE = /^\d{8}$/;

const rateLimited = async (ip, max = 10, windowMs = 60 * 1000, prefix = 'link') => {
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

const GLOBAL_FAIL_REF = () => db.collection('rateLimits').doc('global_link_failures');
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

export const linkLookup = onRequest({ cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 10 }, async (req, res) => {
  // Reject malformed input BEFORE the Firestore-backed rate limiter, so obviously-bad
  // spam can't generate rate-limit writes (the limiter would otherwise be a cost vector).
  const code = String(req.query.code || '');
  if (!CODE.test(code)) return res.status(400).json({ error: 'bad_code' });

  if (await rateLimited(req.ip)) return res.status(429).json({ error: 'rate_limited' });
  if (await globalFailuresExceeded()) return res.status(429).json({ error: 'rate_limited' });

  const q = await db.collection('linkSessions').where('code', '==', code).limit(1).get();
  const doc = q.docs[0];
  const s = doc?.data();
  if (!doc || s.status !== 'pending') {
    await bumpGlobalFailure();
    return res.status(404).json({ error: 'invalid_code' });
  }
  if (Date.now() > s.expiresAt) return res.status(410).json({ error: 'expired_code' });

  // Only the issuer's public key + the (secret) doc id — never any key material.
  res.json({ linkId: doc.id, pubA: s.pubA });
});

// ── Agent capability relay ───────────────────────────────────────────────────
// The MCP bridge is NOT Firebase-authed, so it can't read Firestore directly (unlike the
// device-link joiner). This public, rate-limited function lets it POLL for the capability
// the wallet deposited into agentSessions/{sessionId}. The wallet writes the doc directly
// (authed, under firestore.rules); the capability is ECDH-encrypted to the agent's transport
// key, so this only ever returns ciphertext (+ the wallet's ephemeral pub + audience). The
// sessionId is a 256-bit unguessable id; per-IP rate-limiting bounds abuse.
const HEX64_SESSION = /^[0-9a-f]{64}$/i;

export const agentCapabilityPoll = onRequest(
  { cors: true, maxInstances: 5, memory: '256MiB', timeoutSeconds: 10 },
  async (req, res) => {
    const sessionId = String(req.query.sessionId || '');
    if (!HEX64_SESSION.test(sessionId)) return res.status(400).json({ error: 'bad_session' });

    if (await rateLimited(req.ip, 30, 60 * 1000, 'agent'))
      return res.status(429).json({ error: 'rate_limited' });

    const snap = await db.collection('agentSessions').doc(sessionId).get();
    if (!snap.exists) return res.status(404).json({ error: 'not_found' });
    const s = snap.data();
    if (Date.now() > s.expiresAt) return res.status(410).json({ error: 'expired' });

    // Ciphertext only — the agent decrypts with its transport private key.
    res.json({
      walletPubE: s.walletPubE,
      encryptedCapability: s.encryptedCapability,
      audience: s.audience,
    });
  },
);
