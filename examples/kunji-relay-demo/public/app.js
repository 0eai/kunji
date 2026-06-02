/* global kunji */
// Externalized so the page can ship a CSP without `script-src 'unsafe-inline'`.
const $ = (id) => document.getElementById(id);

// claims are self-asserted + unverified → render the name as text and only accept a
// picture URL with a safe scheme (https / data:image) before binding it to <img src>.
const safePic = (p) => (typeof p === 'string' && /^(https:|data:image\/)/i.test(p) ? p : null);

// Ask the local server where the public callback lives, then render the widget.
// session-url / poll-url are LOCAL; callback-url is the public Firebase Function.
fetch('/config')
  .then((r) => r.json())
  .then((cfg) => {
    $('hint').textContent = 'Callback relays through ' + cfg.audience + ' — scan with the kunji app.';
    kunji.render($('kbtn'), {
      appName: 'kunji Relay Demo',
      audience: cfg.audience,
      sessionUrl: '/api/session',
      callbackUrl: cfg.callbackUrl,
      pollUrl: '/kunji/status',
      scope: 'profile',
    });
  })
  .catch(() => ($('hint').textContent = 'Could not load /config — is the local server running?'));

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
