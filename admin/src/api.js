import { auth } from './firebase.js';

// Every admin call carries the signed-in user's Firebase ID token; issuerAdminApi gates on the admin claim.
// Same-origin (admin.kunji.cc/api/* → the Function via a Hosting rewrite), so no CORS.
const authHeader = async () => {
  const user = auth.currentUser;
  if (!user) throw new Error('not_signed_in');
  return { Authorization: `Bearer ${await user.getIdToken()}` };
};

const call = async (path, opts = {}) => {
  const res = await fetch(`/api${path}`, {
    ...opts,
    headers: { ...(await authHeader()), ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
  });
  if (res.status === 401) throw new Error('unauthorized');
  if (!res.ok) throw new Error((await res.json().catch(() => ({})))?.error || 'request_failed');
  return res.json();
};

export const fetchLedger = (before) => call(`/ledger${before ? `?before=${before}` : ''}`);
export const fetchStats = () => call('/stats');
export const fetchReviews = () => call('/reviews');

// The pending submission's ID image — fetched with the bearer (the endpoint streams bytes, no public URL),
// returned as a blob object URL to display in an <img>.
export const reviewDoc = async (sid, artifact) => {
  const q = `?sid=${encodeURIComponent(sid)}${artifact ? `&artifact=${encodeURIComponent(artifact)}` : ''}`;
  const res = await fetch(`/api/review/doc${q}`, { headers: await authHeader() });
  if (!res.ok) throw new Error('doc_failed');
  return URL.createObjectURL(await res.blob());
};

export const reviewDecision = (sid, approve, verifiedData) =>
  call('/review/decision', { method: 'POST', body: JSON.stringify({ sid, approve, verifiedData }) });
export const revoke = (type, idx) => call('/revoke', { method: 'POST', body: JSON.stringify({ type, idx }) });
export const unrevoke = (type, idx) => call('/unrevoke', { method: 'POST', body: JSON.stringify({ type, idx }) });

// ── Ops console (observability + data lifecycle) ─────────────────────────────────────────────────────────
export const fetchOpsUsers = () => call('/ops/users');
export const fetchOpsTrends = (days = 30) => call(`/ops/trends?days=${days}`);
export const fetchOpsMetrics = (window = '24h') => call(`/ops/metrics?window=${window}`);
export const fetchDataHealth = () => call('/ops/data-health');
export const purgeExpired = () => call('/ops/purge', { method: 'POST', body: JSON.stringify({}) });

// Signing keys come from the issuer's public .well-known (cross-origin, no auth) — best-effort display.
const ISSUER_ORIGIN = import.meta.env.VITE_ISSUER_ORIGIN || 'https://issuer-kunji-cc.web.app';
export const fetchKeys = async () => {
  const res = await fetch(`${ISSUER_ORIGIN}/.well-known/kunji-issuer.json`);
  if (!res.ok) throw new Error('keys_failed');
  return res.json();
};
