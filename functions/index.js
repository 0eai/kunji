// Signed vault writes. Clients can READ vaults/{vaultId} directly (gated by the
// secret, master-key-derived vaultId), but WRITES are denied by rules and must go
// through this function with an Ed25519 signature from the vault write key (also
// master-key-derived). The function never sees the master key or plaintext — only the
// vault PUBLIC key, signatures, and already-encrypted app blobs.
import { onRequest } from 'firebase-functions/v2/https';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
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

export const vaultWrite = onRequest({ cors: true }, async (req, res) => {
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
  // existing clients omit it), 'profile' → profile/self (the user's custom profile).
  const isProfile = kind === 'profile';

  // 1. shape
  if (
    !HEX64.test(vaultId || '') ||
    !SAFE_ID.test(appId || '') ||
    (kind !== undefined && kind !== 'app' && kind !== 'profile') ||
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
    : vaultRef.collection('apps').doc(appId);
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
        tx.set(targetRef, { ...docPayload, createdAt });
      }
    });
  } catch (e) {
    if (e?.message === 'not_authorized') return res.status(403).json({ error: 'not_authorized' });
    return res.status(500).json({ error: 'write_failed' });
  }

  res.json({ status: 'ok' });
});
