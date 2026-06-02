/* global kunji */
// Externalized so the page can ship a CSP without `script-src 'unsafe-inline'`.
const $ = (id) => document.getElementById(id);

// claims are self-asserted + unverified → render the name as text and only accept a
// picture URL with a safe scheme (https / data:image) before binding it to <img src>.
const safePic = (p) => (typeof p === 'string' && /^(https:|data:image\/)/i.test(p) ? p : null);

// Render the official button; callbackUrl is absolute (same origin as this page).
kunji.render($('kbtn'), {
  appName: 'kunji Node Demo',
  audience: location.hostname,
  sessionUrl: '/api/session',
  callbackUrl: location.origin + '/kunji/callback',
  pollUrl: '/kunji/status',
  scope: 'profile', // ask kunji to OFFER a custom profile (the user may decline)
});

document.addEventListener('kunji:success', (e) => {
  const { sub, claims } = e.detail;
  // Prefer the consented custom profile; else the default identity from `sub`.
  const def = kunji.handle(sub);
  $('name').textContent = (claims && claims.name) || def.name;
  $('avatar').src = safePic(claims && claims.picture) || def.avatarDataUri;
  $('origin').textContent =
    claims && (claims.name || claims.picture)
      ? 'shared from their kunji profile'
      : 'default identity (from your ID)';
  $('sub').textContent = sub;
  $('out').hidden = true;
  $('in').hidden = false;
});

$('logout').onclick = () => {
  $('in').hidden = true;
  $('out').hidden = false;
};
