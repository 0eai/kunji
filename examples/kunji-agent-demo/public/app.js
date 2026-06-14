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
let rpSessionId = null; // the RP session the agent logged into — drives the step-up showcase below
let stepupPoll = null;
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
    agentPoll = setInterval(() => pollAgent(r.sessionId), 3000);
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
    // Reveal the step-up showcase: the agent has `login` but not read:profile yet.
    rpSessionId = r.rpSessionId;
    if (rpSessionId) $('stepupBox').hidden = false;
  } else {
    $('agentStatus').textContent = 'Authorization failed: ' + (r.error || r.status);
  }
  if (r.io) {
    $('agentIoPre').textContent = JSON.stringify(r.io, null, 2);
    $('agentIo').hidden = false;
  }
};

// ── STEP-UP (push-relay.md Transport ①): call a scope-gated action with the agent's session; on a
// 403 insufficient_scope, ask the user for the missing scope on the SAME relay (a deep link opens the
// wallet's re-consent sheet), poll until approved, then retry with the broader session. No new infra. ──
$('tryScoped').onclick = async () => {
  $('stepupResult').hidden = true;
  $('stepupStatus').textContent = 'Calling /api/profile…';
  let resp, body;
  try {
    resp = await fetch(`/api/profile?sessionId=${encodeURIComponent(rpSessionId)}`);
    body = await resp.json();
  } catch {
    $('stepupStatus').textContent = 'Network error.';
    return;
  }
  if (resp.status === 200) {
    $('stepupStatus').textContent = '200 — granted.';
    $('stepupResult').textContent = JSON.stringify(body, null, 2);
    $('stepupResult').hidden = false;
    return;
  }
  if (resp.status === 403 && body.error === 'insufficient_scope') {
    $('stepupStatus').textContent = `403 insufficient_scope — needs “${body.need}”.`;
    await startStepUp();
  } else {
    $('stepupStatus').textContent = `${resp.status} ${body.error || ''}`;
  }
};

const startStepUp = async () => {
  let r;
  try {
    r = await fetch('/agent/stepup', { method: 'POST' }).then((x) => x.json());
  } catch {
    $('stepupStatus').textContent = 'Could not start step-up — is the relay reachable?';
    return;
  }
  $('stepupFlow').hidden = false;
  $('stepupLink').href = r.deepLink || '#';
  $('stepupCode').textContent = r.code || '— (scan or paste)';
  if (r.qrDataUri) {
    $('stepupQr').src = r.qrDataUri;
    $('stepupQr').hidden = false;
  }
  $('stepupPollStatus').textContent = 'Waiting for approval…';
  clearInterval(stepupPoll);
  stepupPoll = setInterval(() => pollStepUp(r.sessionId), 3000);
};

const pollStepUp = async (sessionId) => {
  let r;
  try {
    r = await fetch(`/agent/poll?sessionId=${encodeURIComponent(sessionId)}`).then((x) => x.json());
  } catch {
    return; // transient; keep polling
  }
  if (r.status === 'pending') return;
  clearInterval(stepupPoll);
  if (r.status !== 'approved') {
    $('stepupPollStatus').textContent = 'Step-up failed: ' + (r.error || r.status);
    return;
  }
  $('stepupPollStatus').innerHTML = `✓ broader capability · scope: ${escapeHtml((r.scope || []).join(', '))}`;
  // Retry the gated action with the NEW (broader) session.
  try {
    const resp = await fetch(`/api/profile?sessionId=${encodeURIComponent(r.rpSessionId)}`);
    const body = await resp.json();
    $('stepupStatus').textContent = `Retried /api/profile → ${resp.status}`;
    $('stepupResult').textContent = JSON.stringify(body, null, 2);
    $('stepupResult').hidden = false;
  } catch {
    $('stepupStatus').textContent = 'Retry network error.';
  }
};

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
