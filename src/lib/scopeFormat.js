// Human-readable rendering of scope constraints for the consent UI (CAPABILITY_ROADMAP §1.3).
// Pure, dependency-free. kunji does NOT enforce scope semantics — the RP does (see docs/scope.md
// §2, "a grammar, not a registry") — this only makes the consent screen clearer to read. Reserved
// labels (login/profile/offline_access) and untrusted RP-supplied `scopeLabels` are rendered by the
// consent component itself; this module handles the constraint dimensions (max/resource/…).

// Parse an amount like "50USD" / "50 USD" / "50" → { n, ccy }. Mirrors parseAmount in
// src/lib/capability.js (kept local so this module stays pure + standalone).
const parseAmount = (v) => {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]{0,8})\s*$/.exec(String(v));
  return m ? { n: parseFloat(m[1]), ccy: m[2].toUpperCase() } : null;
};

const CCY_SYMBOL = { USD: '$', EUR: '€', GBP: '£', JPY: '¥', INR: '₹', CAD: 'CA$', AUD: 'A$' };

// "50USD" → "$50"; "100 EUR" → "€100"; "5 widgets" → "5 widgets"; "50" → "50".
const formatAmount = (v) => {
  const a = parseAmount(v);
  if (!a) return String(v);
  if (!a.ccy) return `${a.n}`;
  const sym = CCY_SYMBOL[a.ccy];
  return sym ? `${sym}${a.n}` : `${a.n} ${a.ccy}`;
};

// One constraint (key/value) → prose. Known dimensions get friendly text; anything else falls back
// to a readable "key value" so an RP's custom constraint still renders sensibly.
export const formatConstraint = (key, value) => {
  switch (key) {
    case 'max':
      return `up to ${formatAmount(value)}`;
    case 'resource':
      return `resource ${value}`;
    case 'maxUses': {
      const n = Number(value);
      return Number.isFinite(n) ? `${n} use${n === 1 ? '' : 's'}` : `max uses ${value}`;
    }
    case 'rateBudget':
      return `rate ${value}`;
    default:
      return `${key} ${value}`;
  }
};

// Every constraint on a scope item (all keys except `id`) → a joined prose string, or '' if none.
// Accepts a string scope ('read:orders' → '') or an object scope ({ id, ...constraints }).
export const formatConstraints = (item) => {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return '';
  return Object.entries(item)
    .filter(([k]) => k !== 'id')
    .map(([k, v]) => formatConstraint(k, v))
    .join(' · ');
};
