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
