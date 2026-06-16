// Revocation-reliability helpers (CAPABILITY_ROADMAP §1.2).
//
// kunji cannot ENFORCE revocation (there is no kunji-side capability server in the agent↔RP path),
// so revocation is advisory: an RP checks the signed `revocations/{jti}` denylist via
// verifyCapabilityAssertion's `getRevocation`, and the SHORT TTL is the real backstop. These
// constants give a shared, sane default so sensitive scopes don't get long-lived grants. They are
// guidance for the MINTING side (wallet/RP choosing `ttlSeconds`) — the verifier always enforces the
// `exp` that was actually minted. See docs/scope.md and the README.

// Recommended max capability lifetime (seconds) by scope verb/family. Lower = safer (less revocation
// latency exposure). Money/admin are short; read-only can be long.
export const TTL_GUIDANCE = {
  payments: 300, // 5 min  — money movement
  admin: 300, // 5 min  — privileged / destructive
  write: 3600, // 1 hour — mutations
  delete: 300, // 5 min  — destructive
  read: 86400, // 24 hours — read-only
  profile: 86400, // 24 hours — low-risk
  default: 3600, // 1 hour — unknown/namespaced custom scope
};

// The verb of a scope id is the part before the first ':' (e.g. 'payments:send' → 'payments').
// Reserved bare scopes ('login'/'profile'/'offline_access') have no verb; map what we can.
const verbOf = (id) => {
  const s = String(id || '');
  const i = s.indexOf(':');
  return i > 0 ? s.slice(0, i) : s;
};

// Recommended TTL (seconds) for a single scope id or `{ id, ... }` item.
export const recommendedTtl = (scope) => {
  const id = typeof scope === 'string' ? scope : scope?.id;
  return TTL_GUIDANCE[verbOf(id)] ?? TTL_GUIDANCE.default;
};

// Recommended TTL for a whole scope list = the STRICTEST (smallest) of its members. A capability is
// only as safe as its most sensitive grant, so a payments+read capability should expire on the
// payments clock. Empty/invalid list → the default.
export const recommendedTtlForScopes = (scope) => {
  if (!Array.isArray(scope) || scope.length === 0) return TTL_GUIDANCE.default;
  return scope.reduce((min, item) => Math.min(min, recommendedTtl(item)), Infinity);
};
