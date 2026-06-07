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
