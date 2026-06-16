// Short-lived OpenID4VCI authorization_code flow context, keyed by the PKCE `state`.
//
// The auth-code on-ramp navigates the whole tab to the issuer's /authorize and back, so we stash the
// per-flow context where it survives that same-tab round-trip: sessionStorage (per-tab, per-origin,
// cleared when the tab closes; the issuer's origin can't read it). The `codeVerifier` NEVER leaves the
// device — only its S256 challenge is sent. `state` is the CSRF anchor: it's matched on return and the
// context is single-use (taken = deleted), so a replayed/forged ?code= with a stale state can't redeem.
const KEY = 'kunji_oid4vc_auth';
const MAX_AGE_MS = 15 * 60 * 1000; // a flow that hasn't completed in 15 min is stale

const readAll = () => {
  try {
    return JSON.parse(sessionStorage.getItem(KEY)) || {};
  } catch {
    return {};
  }
};
const writeAll = (map) => {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(map));
  } catch {
    /* sessionStorage unavailable (private mode / disabled) — the flow will fail closed on return */
  }
};

// Persist the context for an in-flight flow. Prunes stale entries so the store can't grow unbounded.
export const saveAuthContext = (state, ctx) => {
  const now = Date.now();
  const map = readAll();
  for (const [k, v] of Object.entries(map)) {
    if (!v || typeof v.savedAt !== 'number' || now - v.savedAt > MAX_AGE_MS) delete map[k];
  }
  map[state] = { ...ctx, savedAt: now };
  writeAll(map);
};

// Retrieve AND remove the context for `state` (single-use). Returns null on unknown/stale state.
export const takeAuthContext = (state) => {
  if (!state) return null;
  const map = readAll();
  const ctx = map[state];
  if (!ctx) return null;
  delete map[state];
  writeAll(map);
  if (typeof ctx.savedAt !== 'number' || Date.now() - ctx.savedAt > MAX_AGE_MS) return null;
  return ctx;
};
