// Same-origin calls to the issuer Functions (issuer.kunji.cc). A login session token (from "Sign in with
// kunji") is held in localStorage so a verification is recoverable across refresh / tab-close / device.
const SESSION_KEY = 'kunji_issuer_session';
export const getToken = () => localStorage.getItem(SESSION_KEY) || '';
export const setToken = (t) => (t ? localStorage.setItem(SESSION_KEY, t) : localStorage.removeItem(SESSION_KEY));

const j = async (r) => {
  if (!r.ok) {
    const e = new Error((await r.json().catch(() => ({})))?.error || 'request_failed');
    e.status = r.status; // callers distinguish 401 (re-login) / 404 (gone) from transient errors
    throw e;
  }
  return r.json();
};
const authHeaders = () => {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
};
const post = (path, body, auth = false) =>
  fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(auth ? authHeaders() : {}) }, body: JSON.stringify(body) }).then(j);
const get = (path, auth = false) => fetch(path, { headers: auth ? authHeaders() : {} }).then(j);

// Catalog + login (no auth)
export const fetchCatalog = () => get('/catalog');
export const loginSession = () => post('/kunji/session', {});
export const loginStatus = (sessionId) => get(`/kunji/status?sessionId=${encodeURIComponent(sessionId)}`);

// Verification (authed by the session token)
export const myVerifications = () => get('/verify/mine', true);
export const startVerify = (type, method) => post('/verify/start', { type, method }, true);
export const uploadDoc = (sid, image, contentType) => post('/verify/upload', { sid, image, contentType }, true);
export const uploadLiveness = (sid, video, contentType) => post('/verify/liveness-upload', { sid, video, contentType }, true);
export const checkStatus = (sid) => get(`/verify/status?sid=${encodeURIComponent(sid)}`);
export const getOffer = (sid) => get(`/credential-offer?sid=${encodeURIComponent(sid)}`, true);
// Re-add an already-earned credential to a wallet (no session, no re-verification).
export const getOfferByType = (type) => get(`/credential-offer?type=${encodeURIComponent(type)}`, true);
