/* global kunji */
// Externalized so the page can ship a CSP without `script-src 'unsafe-inline'`.
const $ = (id) => document.getElementById(id);

// claims are self-asserted + unverified → render the name as text and only accept a
// picture URL with a safe scheme (https / data:image) before binding it to <img src>.
const safePic = (p) => (typeof p === 'string' && /^(https:|data:image\/)/i.test(p) ? p : null);

// Render the official button; callbackUrl is absolute (same origin as this page).
kunji.render($('kbtn'), {
  appName: 'kunji Agent Demo',
  audience: location.hostname,
  sessionUrl: '/api/session',
  callbackUrl: location.origin + '/kunji/callback',
  pollUrl: '/kunji/status',
  scope: 'profile', // ask kunji to OFFER a custom profile (the user may decline)
});

// Render the signed-in view. `agent`/`scope` come from /kunji/status: an agent login
// (POST /kunji/agent) resolves to the SAME `sub` as the human, so the identity is shared —
// only the badge distinguishes how the session was approved.
const showSignedIn = ({ sub, claims, agent, scope }) => {
  // Prefer the consented custom profile; else the default identity from `sub`.
  const def = kunji.handle(sub);
  $('name').textContent = (claims && claims.name) || def.name;
  $('avatar').src = safePic(claims && claims.picture) || def.avatarDataUri;
  $('origin').textContent =
    claims && (claims.name || claims.picture)
      ? 'shared from their kunji profile'
      : 'default identity (from your ID)';
  $('sub').textContent = sub;
  if (agent) {
    $('agentBadge').textContent = `signed in by an authorized agent · scope: ${(scope || []).join(', ')}`;
    $('agentBadge').hidden = false;
  }
  $('out').hidden = true;
  $('in').hidden = false;
};

document.addEventListener('kunji:success', async (e) => {
  const { sub, claims, sessionId } = e.detail;
  // The success event carries the human identity. Read the session once more to learn whether
  // it was approved by an agent (it wasn't, for this widget flow) and the granted scope.
  let agent = false;
  let scope = null;
  try {
    const s = await fetch(`/kunji/status?sessionId=${encodeURIComponent(sessionId)}`).then((r) => r.json());
    agent = !!s.agent;
    scope = s.scope;
  } catch {
    /* status is best-effort; fall back to the event detail */
  }
  showSignedIn({ sub, claims, agent, scope });
});

$('logout').onclick = () => {
  $('agentBadge').hidden = true;
  $('in').hidden = true;
  $('out').hidden = false;
};

// ── "Authorize an agent" — this page acts as a web-hosted agent. POST /agent/start gets a 6-digit
// code + QR from the live relay; the user approves in the wallet; we poll /agent/poll until the
// server has received the capability over the relay and logged itself in here. ──
let agentPoll = null;
$('agentStart').onclick = async () => {
  $('agentStart').disabled = true;
  $('agentStart').textContent = 'Starting…';
  try {
    const r = await fetch('/agent/start', { method: 'POST' }).then((x) => x.json());
    $('agentFlow').hidden = false;
    $('agentCode').textContent = r.code || '— (relay unavailable; scan or paste)';
    if (r.qrDataUri) {
      $('agentQr').src = r.qrDataUri;
      $('agentQr').hidden = false;
    }
    $('agentStatus').textContent = 'Waiting for approval…';
    clearInterval(agentPoll);
    agentPoll = setInterval(() => pollAgent(r.sessionId), 2000);
  } catch {
    $('agentStatus').textContent = 'Could not start — is the relay reachable?';
    $('agentStart').disabled = false;
    $('agentStart').textContent = 'Authorize an agent →';
  }
};

const pollAgent = async (sessionId) => {
  let r;
  try {
    r = await fetch(`/agent/poll?sessionId=${encodeURIComponent(sessionId)}`).then((x) => x.json());
  } catch {
    return; // transient; keep polling
  }
  if (r.status === 'pending') return;
  clearInterval(agentPoll);
  if (r.status === 'approved') {
    $('agentCode').textContent = '✓';
    $('agentStatus').innerHTML =
      `Agent signed in as <b>${escapeHtml((r.sub || '').slice(0, 16))}…</b> · scope: ` +
      escapeHtml((r.scope || []).join(', '));
  } else {
    $('agentStatus').textContent = 'Authorization failed: ' + (r.error || r.status);
  }
  if (r.io) {
    $('agentIoPre').textContent = JSON.stringify(r.io, null, 2);
    $('agentIo').hidden = false;
  }
};

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
