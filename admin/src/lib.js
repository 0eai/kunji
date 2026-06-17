import { useState, useEffect } from 'react';

// ── Hash routing (dependency-free; mirrors the demo SPA's pattern) ───────────────────────────────────────
export const ROUTES = [
  { id: 'overview', label: 'Overview' },
  { id: 'reviews', label: 'Reviews' },
  { id: 'ledger', label: 'Ledger' },
  { id: 'users', label: 'Users' },
  { id: 'data', label: 'Data health' },
  { id: 'metrics', label: 'Metrics' },
  { id: 'keys', label: 'Keys' },
];
const IDS = ROUTES.map((r) => r.id);

const currentRoute = () => {
  const h = (typeof location !== 'undefined' ? location.hash : '').replace(/^#\/?/, '');
  return IDS.includes(h) ? h : 'overview';
};

export const useHashRoute = () => {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const on = () => setRoute(currentRoute());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return [route, (id) => (location.hash = id)];
};

// ── Formatters ───────────────────────────────────────────────────────────────────────────────────────────
// Compact display of a credential's coarse claims: age_over_N → ≥N, other true booleans → the key,
// key:value → "key:value" (false booleans omitted).
export const claimSummary = (c) => {
  if (!c || typeof c !== 'object') return '—';
  const parts = Object.entries(c)
    .map(([k, v]) => {
      if (k.startsWith('age_over_')) return v ? k.replace('age_over_', '≥') : null;
      if (v === true) return k;
      if (v === false) return null;
      return `${k}:${v}`;
    })
    .filter(Boolean);
  return parts.join(' ') || 'none';
};

export const fmtNum = (n) => (n == null ? '—' : Number(n).toLocaleString());

export const fmtAge = (ms) => {
  if (ms == null) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 90) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 90) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
};

export const fmtMs = (n) => (n == null ? '—' : `${n}ms`);
export const fmtPct = (r) => (r == null ? '—' : `${(r * 100).toFixed(r >= 0.01 ? 1 : 2)}%`);
export const fmtDate = (ms) => (ms ? new Date(ms).toLocaleString() : '');
export const fmtDay = (ms) => (ms ? new Date(ms).toISOString().slice(0, 10) : '');
