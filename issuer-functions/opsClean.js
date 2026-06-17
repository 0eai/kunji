// Operator data-cleanup core (pure, no Firebase) — the "is this doc provably dead?" predicates + the sweep
// plan, shared by the scheduled sweep (issuerCleanup) and the operator-triggered purge (/api/ops/purge).
// Kept pure so the SAFETY rules — only ever delete data that is definitely expired, NEVER a live doc, the
// ledger, nullifiers, issuerVerified/issuerUsers, or a vault — are unit-tested in isolation. index.js does
// the actual querying/batched deletes; this module only decides WHAT is dead.

// The longest capability TTL the wallet offers is 7 days; a revocation older than this floor is for a
// capability that has definitely already expired (RPs reject an expired cap regardless), so the denylist
// entry is dead weight and safe to drop. 30 days is a generous safety margin over the 7-day max.
export const MAX_CAP_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const REVOCATION_FLOOR_MS = 30 * 24 * 60 * 60 * 1000;
// A per-IP rate-limit bucket is dead once its sliding window has elapsed (the limiter resets a stale bucket
// anyway). Matches the limiters' default window in functions/index.js + issuer-functions/index.js.
export const RATELIMIT_WINDOW_MS = 60 * 1000;

// Normalize a stored time field to epoch-ms: a plain number (app `expiresAt`/`revokedAt`/`start`), a Firestore
// Timestamp (issuer `ttl`: {_seconds,_nanoseconds} or a real Timestamp with .toMillis()), or a Date.
export const toMillis = (v) => {
  if (v == null) return null;
  if (typeof v === 'number') return v;
  if (typeof v.toMillis === 'function') return v.toMillis();
  if (typeof v._seconds === 'number') return v._seconds * 1000 + Math.floor((v._nanoseconds || 0) / 1e6);
  if (v instanceof Date) return v.getTime();
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

// The ONLY collections the sweep/purge may touch. Each: the time field, its type (so index.js builds a typed
// `<` cutoff), and how far past that time a doc must be to count as dead (`deadAfterMs`). Anything NOT listed
// here is never swept — that's the allow-list that protects the ledger (issuerCredentials), issuerStatusList,
// issuerNullifiers (Sybil floor), issuerVerified, issuerUsers, vaults/*, and opsDaily.
export const SWEEP_SPECS = [
  // App relay/session docs — dead once past `expiresAt` (belt-and-suspenders behind the Firestore TTL policy).
  { collection: 'agentSessions', tsField: 'expiresAt', tsType: 'number', deadAfterMs: 0 },
  { collection: 'agentRequests', tsField: 'expiresAt', tsType: 'number', deadAfterMs: 0 },
  { collection: 'credentialSessions', tsField: 'expiresAt', tsType: 'number', deadAfterMs: 0 },
  { collection: 'linkSessions', tsField: 'expiresAt', tsType: 'number', deadAfterMs: 0 },
  { collection: 'pushChannels', tsField: 'expiresAt', tsType: 'number', deadAfterMs: 0 },
  // Issuer relay/session docs — `ttl` is a Firestore Timestamp.
  { collection: 'issuerOffers', tsField: 'ttl', tsType: 'timestamp', deadAfterMs: 0 },
  { collection: 'issuerTokens', tsField: 'ttl', tsType: 'timestamp', deadAfterMs: 0 },
  { collection: 'issuerLoginSessions', tsField: 'ttl', tsType: 'timestamp', deadAfterMs: 0 },
  { collection: 'issuerSessions', tsField: 'ttl', tsType: 'timestamp', deadAfterMs: 0 },
  { collection: 'verificationSessions', tsField: 'ttl', tsType: 'timestamp', deadAfterMs: 0 },
  // Per-IP rate-limit buckets — dead once the window elapsed. Unbounded today (no TTL field).
  { collection: 'rateLimits', tsField: 'start', tsType: 'number', deadAfterMs: RATELIMIT_WINDOW_MS },
  { collection: 'issuerRateLimits', tsField: 'start', tsType: 'number', deadAfterMs: RATELIMIT_WINDOW_MS },
  // Capability revocations — dead only past the 30-day cap-expiry safety floor (underlying cap is long gone).
  { collection: 'revocations', tsField: 'revokedAt', tsType: 'number', deadAfterMs: REVOCATION_FLOOR_MS },
];

/** True only if a doc's stored time field is older than `now - spec.deadAfterMs` (i.e. provably dead). A doc
 *  with a missing/unparseable time field is treated as NOT dead (never deleted) — fail closed. */
export const isDeadDoc = (data, spec, now) => {
  const t = toMillis(data?.[spec.tsField]);
  if (t == null) return false; // no usable timestamp → keep it (never guess-delete)
  return t < now - (spec.deadAfterMs || 0);
};

/** The sweep plan: per-collection the field + the epoch-ms cutoff such that `tsField < cutoff` ⇒ dead. index.js
 *  turns each cutoff into the typed value (`Timestamp.fromMillis` for `timestamp` fields, the number itself for
 *  `number` fields) for the Firestore range query. */
export const sweepPlan = (now) =>
  SWEEP_SPECS.map((s) => ({ collection: s.collection, tsField: s.tsField, tsType: s.tsType, cutoffMs: now - (s.deadAfterMs || 0) }));
