// Same-origin calls to the issuer Functions (issuer.kunji.cc). No auth — this is the public verify flow.
const j = async (r) => {
  if (!r.ok) throw new Error((await r.json().catch(() => ({})))?.error || 'request_failed');
  return r.json();
};
const post = (path, body) =>
  fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(j);

export const startVerify = () => post('/verify/start', { type: 'age', method: 'document-review' });
export const uploadDoc = (sid, image, contentType) => post('/verify/upload', { sid, image, contentType });
export const checkStatus = (sid) => fetch(`/verify/status?sid=${encodeURIComponent(sid)}`).then(j);
export const getOffer = (sid) => fetch(`/credential-offer?sid=${encodeURIComponent(sid)}`).then(j);
