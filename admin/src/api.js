import { auth } from './firebase.js';

// Every admin call carries the signed-in user's Firebase ID token; issuerAdminApi gates on the admin claim.
// Same-origin (admin.kunji.cc/api/* → the Function via a Hosting rewrite), so no CORS.
const call = async (path, opts = {}) => {
  const user = auth.currentUser;
  if (!user) throw new Error('not_signed_in');
  const token = await user.getIdToken();
  const res = await fetch(`/api${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
    },
  });
  if (res.status === 401) throw new Error('unauthorized');
  if (!res.ok) throw new Error((await res.json().catch(() => ({})))?.error || 'request_failed');
  return res.json();
};

export const fetchLedger = (before) => call(`/ledger${before ? `?before=${before}` : ''}`);
export const fetchStats = () => call('/stats');
export const revoke = (idx) => call('/revoke', { method: 'POST', body: JSON.stringify({ idx }) });
export const unrevoke = (idx) => call('/unrevoke', { method: 'POST', body: JSON.stringify({ idx }) });
