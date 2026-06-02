/* global kunji, firebase */
// Externalized so the page can ship a CSP without `script-src 'unsafe-inline'`.
const $ = (id) => document.getElementById(id);
const auth = firebase.auth();
const db = firebase.firestore();

// claims are self-asserted + unverified → render the name as text and only accept a
// picture URL with a safe scheme (https / data:image) before binding it to <img src>.
const safePic = (p) => (typeof p === 'string' && /^(https:|data:image\/)/i.test(p) ? p : null);

// Render the official button. callbackUrl is absolute (the wallet POSTs to it);
// everything is same-origin on your Hosting/custom domain → audience = that domain.
kunji.render($('kbtn'), {
  appName: 'kunji Self-Hosted Demo',
  audience: location.hostname,
  sessionUrl: '/api/session',
  callbackUrl: location.origin + '/kunji/callback',
  pollUrl: '/kunji/status',
  scope: 'profile',
});
$('hint').textContent = 'Scan with the kunji app — no password, no account to create.';

function renderAccount(user, sub, claims) {
  // Prefer the consented custom profile; else the default identity from `sub`.
  const def = kunji.handle(sub);
  $('name').textContent = (claims && claims.name) || def.name;
  $('avatar').src = safePic(claims && claims.picture) || def.avatarDataUri;
  $('origin').textContent =
    claims && (claims.name || claims.picture) ? 'from their kunji profile' : 'default identity';
  $('acct').textContent = JSON.stringify(user || { sub }, null, 2);
  $('out').hidden = true;
  $('in').hidden = false;
}

async function showSignedIn(sub, claims) {
  // request.auth.uid === sub, so this read is allowed by the security rules.
  const snap = await db.collection('users').doc(sub).get();
  renderAccount(snap.exists ? snap.data() : null, sub, claims);
}

// Returning visit: the custom-token session persists, so restore it.
auth.onAuthStateChanged((u) => {
  if (u && $('in').hidden) showSignedIn(u.uid, null).catch(() => {});
});

document.addEventListener('kunji:success', async (e) => {
  const { sub, claims, customToken } = e.detail;
  if (!customToken) {
    $('hint').textContent = 'Signed in, but no token returned — check the callback Function.';
    return;
  }
  await auth.signInWithCustomToken(customToken); // uid === sub
  await showSignedIn(sub, claims);
});

$('logout').onclick = async () => {
  await auth.signOut();
  $('in').hidden = true;
  $('out').hidden = false;
};
