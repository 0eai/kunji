/**
 * "Sign in with kunji" drop-in widget — rp.js
 *
 * Renders the official button and runs the whole login flow inside a shadow root.
 * It is a PURE CLIENT: it talks only to the relying party's OWN endpoints
 * (session / poll) and draws a QR. It never contacts a kunji server.
 *
 * Usage:
 *   <script src="https://kunji.cc/rp.js"></script>
 *   <div data-kunji-signin
 *        data-app-name="Your App"
 *        data-audience="yourapp.com"
 *        data-session-url="/kunji/session"     POST  -> { sessionId, challenge, code?, expiresAt }
 *        data-callback-url="/kunji/callback"    (wallet POSTs the signed assertion here)
 *        data-poll-url="/kunji/status"          GET ?sessionId= -> { status, sub }
 *        data-redirect="/dashboard"></div>      (optional; else listen for 'kunji:success')
 */
import QRCode from 'qrcode';

const APP_URL_DEFAULT = 'https://app.kunji.cc';
const POLL_MS = 2000;

const b64url = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Official key mark (dark ink), reused from the kunji brand icon.
const KEY_SVG = `<svg viewBox="0 0 512 512" aria-hidden="true"><g transform="rotate(-40 256 256)" fill="currentColor">
  <path fill-rule="evenodd" d="M 282,256 A 86,86 0 0,1 110,256 A 86,86 0 0,1 282,256 Z M 244,256 A 48,48 0 0,0 148,256 A 48,48 0 0,0 244,256 Z"/>
  <rect x="196" y="238" width="200" height="36" rx="18"/><rect x="356" y="274" width="28" height="48" rx="8"/><rect x="314" y="274" width="28" height="36" rx="8"/>
</g></svg>`;

const CSS = `
:host { all: initial; }
*, *::before, *::after { box-sizing: border-box; }
.btn {
  display: inline-flex; align-items: center; gap: 10px; cursor: pointer;
  font-family: 'Geist Variable','Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  font-size: 15px; font-weight: 600; letter-spacing: -0.01em;
  border: 0; border-radius: 999px; padding: 11px 20px;
  background: #f59e0b; color: #1a1a18; transition: background .15s ease;
}
.btn:hover { background: #d97706; }
.btn .mark { width: 18px; height: 18px; display: inline-block; }
.btn.dark { background: #1a1a18; color: #faf9f6; }
.btn.dark:hover { background: #000; }

.overlay {
  position: fixed; inset: 0; z-index: 2147483000;
  display: flex; align-items: flex-end; justify-content: center;
  background: rgba(26,26,24,.28); backdrop-filter: blur(2px);
  font-family: 'Geist Variable','Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  animation: kf .18s ease-out;
}
@media (min-width:640px){ .overlay{ align-items:center; } }
.sheet {
  width: 100%; max-width: 25rem; background: #fff; color: #1a1a18;
  border: 1px solid #e7e5e0; border-radius: 24px 24px 0 0;
  padding: 22px 24px max(22px, env(safe-area-inset-bottom));
  animation: ksu .26s cubic-bezier(.22,1,.36,1);
}
@media (min-width:640px){ .sheet{ border-radius:22px; padding:26px; animation:kf .2s ease-out; } }
@keyframes kf { from{opacity:0} to{opacity:1} }
@keyframes ksu { from{transform:translateY(100%)} to{transform:translateY(0)} }
@media (prefers-reduced-motion: reduce){ .overlay,.sheet{animation:none} }

.top { display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; }
.title { display:flex; align-items:center; gap:9px; font-size:15px; font-weight:600; }
.title .mark { width:22px; height:22px; border-radius:7px; background:#f59e0b; color:#1c1606; padding:3px; }
.x { background:none; border:0; cursor:pointer; color:#a8a59c; font-size:22px; line-height:1; padding:4px; }
.x:hover{ color:#1a1a18; }
.lead { font-size:13px; color:#6b6b66; margin:-8px 0 16px; }
.lead b { color:#1a1a18; font-weight:600; }

.tabs { display:flex; gap:24px; border-bottom:1px solid #e7e5e0; margin-bottom:18px; }
.tab { background:none; border:0; border-bottom:2px solid transparent; margin-bottom:-1px;
  padding:0 0 8px; cursor:pointer; font-size:14px; font-weight:500; color:#a8a59c; }
.tab:hover{ color:#6b6b66; }
.tab.on { color:#1a1a18; border-color:#d97706; }

.panel { min-height: 248px; }
.qrbox { display:inline-block; border:1px solid #e7e5e0; border-radius:16px; padding:14px; background:#fff; }
.qrbox img { display:block; width:196px; height:196px; }
.cap { font-size:13px; color:#6b6b66; margin-top:12px; }
.otp { font-family:'Geist Mono Variable',ui-monospace,Menlo,monospace; font-variant-numeric:tabular-nums;
  font-size:38px; letter-spacing:.16em; color:#1a1a18; margin-top:6px; }
.otplabel { font-size:11px; text-transform:uppercase; letter-spacing:.16em; color:#a8a59c; }

.divider { display:flex; align-items:center; gap:12px; color:#a8a59c; font-size:11px;
  text-transform:uppercase; letter-spacing:.14em; margin:18px 0 14px; }
.divider::before,.divider::after{ content:''; flex:1; height:1px; background:#e7e5e0; }

.open { width:100%; display:inline-flex; align-items:center; justify-content:center; gap:9px;
  border:0; border-radius:999px; padding:12px; cursor:pointer; text-decoration:none;
  background:#f59e0b; color:#1a1a18; font-size:14px; font-weight:600; }
.open:hover{ background:#d97706; }
.open .mark{ width:17px; height:17px; }

.expiry { font-size:12px; color:#a8a59c; margin-top:16px; text-align:center; }
.expiry b{ font-family:'Geist Mono Variable',ui-monospace,Menlo,monospace; font-variant-numeric:tabular-nums; color:#6b6b66; font-weight:500; }
.center { text-align:center; }
.note { font-size:14px; color:#6b6b66; padding:28px 0; text-align:center; }
.again { margin-top:12px; background:#f59e0b; color:#1a1a18; border:0; border-radius:999px; padding:10px 18px; font-size:14px; font-weight:600; cursor:pointer; }
.ok { display:flex; flex-direction:column; align-items:center; gap:10px; padding:34px 0; }
.ok .ring { width:48px; height:48px; border-radius:999px; background:#dcfce7; color:#16a34a; display:flex; align-items:center; justify-content:center; font-size:26px; }
.ok p { font-size:15px; font-weight:600; color:#16a34a; }
`;

function el(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function readOpts(node, override = {}) {
  const d = node?.dataset || {};
  return {
    appName: override.appName || d.appName || 'this app',
    audience: override.audience || d.audience || location.hostname,
    sessionUrl: override.sessionUrl || d.sessionUrl,
    callbackUrl: override.callbackUrl || d.callbackUrl,
    pollUrl: override.pollUrl || d.pollUrl,
    redirect: override.redirect || d.redirect || '',
    appUrl: override.appUrl || d.appUrl || APP_URL_DEFAULT,
    theme: override.theme || d.theme || 'light',
    label: override.label || d.label || 'Sign in with kunji',
  };
}

// ── the modal / flow ────────────────────────────────────────────
function openModal(opts, sourceEl) {
  if (!opts.sessionUrl || !opts.pollUrl || !opts.callbackUrl) {
    console.error('[kunji] data-session-url, data-callback-url and data-poll-url are required.');
    return;
  }

  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = CSS;
  root.appendChild(style);

  const overlay = el(`<div class="overlay" role="dialog" aria-modal="true"></div>`);
  const sheet = el(`<div class="sheet"></div>`);
  overlay.appendChild(sheet);
  root.appendChild(overlay);

  const prevOverflow = document.body.style.overflow;
  document.body.style.overflow = 'hidden';

  let timers = [];
  const clearTimers = () => { timers.forEach(clearInterval); timers.forEach(clearTimeout); timers = []; };
  const close = () => { clearTimers(); document.body.style.overflow = prevOverflow; host.remove(); };
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

  let tab = window.matchMedia('(min-width:640px)').matches ? 'qr' : 'otp';
  let currentSessionId = null;

  // `result` is the RP's poll payload, e.g. { status, sub, customToken? }.
  const succeed = (result) => {
    clearTimers();
    sheet.innerHTML = `<div class="ok"><div class="ring">✓</div><p>Signed in</p></div>`;
    const detail = { ...result, sessionId: currentSessionId, audience: opts.audience };
    sourceEl?.dispatchEvent(new CustomEvent('kunji:success', { detail, bubbles: true }));
    document.dispatchEvent(new CustomEvent('kunji:success', { detail }));
    setTimeout(() => {
      close();
      if (opts.redirect) location.assign(opts.redirect);
    }, 700);
  };

  async function start() {
    clearTimers();
    sheet.innerHTML = `<div class="note">Preparing sign-in…</div>`;
    let session;
    try {
      const r = await fetch(opts.sessionUrl, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ audience: opts.audience, callbackUrl: opts.callbackUrl, appName: opts.appName }),
      });
      if (!r.ok) throw new Error('session');
      session = await r.json(); // { sessionId, challenge, code?, expiresAt }
      currentSessionId = session.sessionId;
    } catch {
      sheet.innerHTML = `<div class="note">Couldn't start sign-in.<br><button class="again">Try again</button></div>`;
      sheet.querySelector('.again').onclick = start;
      return;
    }

    const payload = {
      kunjiAuth: 'v2', mode: 'discoverable',
      sessionId: session.sessionId, challenge: session.challenge,
      audience: opts.audience, callbackUrl: opts.callbackUrl,
      appName: opts.appName, expiresAt: session.expiresAt,
      returnUrl: location.href,
    };
    const qrData = JSON.stringify(payload);
    const deepLink = `${opts.appUrl}/?approve=${b64url(qrData)}`;
    let qrImg = '';
    try { qrImg = await QRCode.toDataURL(qrData, { width: 196, margin: 1, color: { dark: '#1a1a18', light: '#ffffff' } }); } catch {}
    const code = session.code || '';

    render();
    function render() {
      sheet.innerHTML = `
        <div class="top">
          <div class="title"><span class="mark">${KEY_SVG}</span> Sign in with kunji</div>
          <button class="x" aria-label="Close">×</button>
        </div>
        <p class="lead">Sign in to <b>${esc(opts.appName)}</b> — no password, no account.</p>
        <div class="tabs">
          <button class="tab ${tab === 'qr' ? 'on' : ''}" data-t="qr">QR</button>
          ${code ? `<button class="tab ${tab === 'otp' ? 'on' : ''}" data-t="otp">OTP</button>` : ''}
        </div>
        <div class="panel">
          ${tab === 'qr' || !code ? `
            <div class="qrbox">${qrImg ? `<img src="${qrImg}" alt="Sign-in QR">` : ''}</div>
            <p class="cap">Scan with the kunji app on your phone.</p>
          ` : `
            <p class="otplabel">Type this code into kunji</p>
            <div class="otp">${code.slice(0, 3)} ${code.slice(3)}</div>
            <p class="cap">Open kunji → enter this code.</p>
          `}
        </div>
        <div class="divider">on this device</div>
        <a class="open" href="${deepLink}"><span class="mark">${KEY_SVG}</span> Sign in with kunji</a>
        <p class="expiry"></p>`;

      sheet.querySelector('.x').onclick = close;
      sheet.querySelectorAll('.tab').forEach((b) => b.onclick = () => { tab = b.dataset.t; render(); });

      // countdown (pauses while tab hidden); on expiry offer a fresh code
      const exp = sheet.querySelector('.expiry');
      const tick = () => {
        if (document.hidden) return;
        const left = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
        if (left <= 0) {
          clearTimers();
          exp.innerHTML = `Code expired. <button class="again">New code</button>`;
          exp.querySelector('.again').onclick = start;
          return;
        }
        exp.innerHTML = `Expires in <b>${left}s</b>`;
      };
      tick();
      timers.push(setInterval(tick, 1000));
    }

    // poll the RP's own status endpoint
    const poll = async () => {
      if (document.hidden) return;
      try {
        const r = await fetch(`${opts.pollUrl}${opts.pollUrl.includes('?') ? '&' : '?'}sessionId=${encodeURIComponent(session.sessionId)}`);
        if (!r.ok) return;
        const s = await r.json();
        if (s.status === 'approved') succeed(s);
      } catch {}
    };
    timers.push(setInterval(poll, POLL_MS));
  }

  start();
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ── button rendering ────────────────────────────────────────────
function render(node, override = {}) {
  if (!node || node.__kunjiMounted) return;
  node.__kunjiMounted = true;
  const opts = readOpts(node, override);
  const root = node.attachShadow ? node.attachShadow({ mode: 'open' }) : node;
  const style = document.createElement('style');
  style.textContent = CSS;
  const btn = el(`<button class="btn ${opts.theme === 'dark' ? 'dark' : ''}"><span class="mark">${KEY_SVG}</span>${esc(opts.label)}</button>`);
  btn.addEventListener('click', () => openModal(opts, node));
  root.appendChild(style);
  root.appendChild(btn);
}

function init() {
  document.querySelectorAll('[data-kunji-signin]').forEach((n) => render(n));
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

window.kunji = {
  render: (elOrSel, opts) => render(typeof elOrSel === 'string' ? document.querySelector(elOrSel) : elOrSel, opts),
  signIn: (opts) => openModal(readOpts(null, opts || {}), null),
  init,
};
