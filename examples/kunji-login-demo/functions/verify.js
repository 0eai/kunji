import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

/**
 * Canonical JSON — keys sorted alphabetically, no whitespace.
 * MUST match kunji's signer in src/lib/crypto/ed25519.js.
 */
export function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return JSON.stringify(obj);
  const sorted = {};
  Object.keys(obj)
    .sort()
    .forEach((k) => {
      sorted[k] = obj[k];
    });
  return JSON.stringify(sorted);
}

const b64 = (s) => Buffer.from(s, 'base64');

/** sub = hex( SHA-256( utf8(publicKeyBase64) ) ) — matches kunji's deriveSubFromPublicKey. */
export function subFromPublicKey(publicKeyBase64) {
  return createHash('sha256').update(publicKeyBase64, 'utf8').digest('hex');
}

/**
 * Pull self-asserted profile claims out of a verified payload, if present.
 * ⚠️ These are signed (tamper-evident) but NOT verified — the user can type anything.
 * Treat as untrusted: HTML-escape `name`, and only render `picture` client-side under
 * a strict CSP (never server-fetch it). Returns null when no claims were shared.
 */
function extractClaims(signedPayload) {
  const c = signedPayload?.claims;
  if (!c || typeof c !== 'object') return null;
  const out = {};
  if (typeof c.name === 'string') out.name = c.name.slice(0, 60);
  if (typeof c.picture === 'string') out.picture = c.picture.slice(0, 2048);
  return out.name || out.picture ? out : null;
}

/**
 * Verify a kunji discoverable-login assertion (spec §6).
 * @returns {{ ok: true, sub: string, claims: object|null } | { ok: false, error: string }}
 */
export function verifyAssertion({ assertion, session, audience, now = Date.now() }) {
  const { publicKey, signedPayload, signedToken } = assertion || {};
  if (!publicKey || !signedPayload || !signedToken)
    return { ok: false, error: 'malformed_assertion' };

  // 1. session exists, fresh, pending
  if (!session) return { ok: false, error: 'unknown_session' };
  if (session.status !== 'pending') return { ok: false, error: 'session_consumed' };
  if (now > session.expiresAt) return { ok: false, error: 'session_expired' };

  // 2. challenge match (anti-replay)
  if (signedPayload.challenge !== session.challenge)
    return { ok: false, error: 'challenge_mismatch' };

  // 3. audience match (anti-relay/phishing)
  if (signedPayload.audience !== audience) return { ok: false, error: 'audience_mismatch' };

  // 4. signature valid over canonical JSON
  let sigOk = false;
  try {
    sigOk = ed25519.verify(
      b64(signedToken),
      new TextEncoder().encode(canonicalJson(signedPayload)),
      b64(publicKey),
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, error: 'bad_signature' };

  // 5. sub integrity
  if (signedPayload.sub !== subFromPublicKey(publicKey))
    return { ok: false, error: 'sub_mismatch' };

  // 6. freshness (±2 min)
  if (Math.abs(now - signedPayload.timestamp) > 120_000)
    return { ok: false, error: 'stale_timestamp' };

  return { ok: true, sub: signedPayload.sub, claims: extractClaims(signedPayload) };
}
