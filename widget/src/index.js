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
import { renderBrandedQr } from '../../src/lib/brandedQr.js';
import { deriveHandle } from '../../src/lib/kunjiHandle.js';
import { encodeCompactQr } from '../../src/lib/qrCodec.js';

const APP_URL_DEFAULT = 'https://app.kunji.cc';
const POLL_MS = 2000;

const b64url = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Official key mark (dark ink), reused from the kunji brand icon.
const KEY_SVG = `<svg viewBox="0 0 512 512" aria-hidden="true"><g transform="rotate(-40 256 256)" fill="none" stroke="currentColor" stroke-width="58" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="240" cy="172" r="56" fill="currentColor"/><path d="M240 172 V398"/><path d="M240 334 L300 314"/><path d="M240 334 L300 358"/>
</g></svg>`;

// The branded QR (styled modules + amber logo on a white quiet-zone plate) is rendered through the
// wallet's canonical renderBrandedQr — one source of truth, so the widget never drifts from the app.

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

/* Section label — organizes the sheet by DEVICE ("another device" / "this device") instead of by method. */
.sect { font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.14em; color:#a8a59c; margin:20px 0 12px; }
.sect:first-of-type { margin-top:4px; }

.panel { }
.qrbox { position:relative; display:inline-block; border:1px solid #e7e5e0; border-radius:16px; padding:12px; background:#fff; line-height:0; }
.qrbox svg { display:block; width:224px; height:224px; }
.cap { font-size:13px; color:#6b6b66; margin-top:12px; }
/* Inline code fallback (replaces the old OTP tab) — shown under the QR / open-app button. */
.codehint { font-size:13px; color:#6b6b66; margin-top:12px; }
.codehint.center { text-align:center; }
/* Lazy OTP: a subtle "Use a code" text button; the 6-digit code is minted/revealed only on click. */
.codeslot { margin-top:12px; }
.codeslot.center { text-align:center; }
.usecode { background:none; border:0; padding:0; cursor:pointer; font-family:inherit;
  font-size:13px; color:#6b6b66; text-decoration:underline; text-underline-offset:2px; }
.usecode:hover { color:#1a1a18; }
.codehint b { font-family:'Geist Mono Variable',ui-monospace,Menlo,monospace; font-variant-numeric:tabular-nums;
  font-size:15px; letter-spacing:.1em; color:#1a1a18; font-weight:600; }

.open { width:100%; display:inline-flex; align-items:center; justify-content:center; gap:9px;
  border:0; border-radius:999px; padding:12px; cursor:pointer; text-decoration:none;
  background:#f59e0b; color:#1a1a18; font-size:14px; font-weight:600; }
.open:hover{ background:#d97706; }
.open .mark{ width:17px; height:17px; }
/* Secondary (outline) variant — the "this device" action on desktop, where the QR is the hero. */
.open.secondary { background:transparent; color:#1a1a18; border:1px solid #e7e5e0; }
.open.secondary:hover{ background:#faf9f6; }

/* Mobile: a phone can't scan its own screen, so the QR is a demoted native disclosure. */
.qrdisc { margin-top:16px; }
.qrdisc summary { list-style:none; cursor:pointer; font-size:13px; color:#6b6b66; padding:2px 0; }
.qrdisc summary::-webkit-details-marker { display:none; }
.qrdisc summary:hover { color:#1a1a18; }
.qrdisc[open] summary { margin-bottom:12px; }

.expiry { font-size:12px; color:#a8a59c; margin-top:18px; text-align:center; }
.expiry b{ font-family:'Geist Mono Variable',ui-monospace,Menlo,monospace; font-variant-numeric:tabular-nums; color:#6b6b66; font-weight:500; }
.center { text-align:center; }
.note { font-size:14px; color:#6b6b66; padding:28px 0; text-align:center; }
.panel.expired { min-height:200px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:16px; text-align:center; }
.panel.expired p { font-size:14px; color:#6b6b66; line-height:1.6; }
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
    // Optional: an endpoint that lazily mints the 6-digit code for an existing session (POST {sessionId}
    // -> {code}). When set, the OTP is only minted on the "Use a code" click (fewer live codes, S5).
    codeUrl: override.codeUrl || d.codeUrl || '',
    redirect: override.redirect || d.redirect || '',
    appUrl: override.appUrl || d.appUrl || APP_URL_DEFAULT,
    theme: override.theme || d.theme || 'light',
    label: override.label || d.label || 'Sign in with kunji',
    // Optional OAuth-style scopes, e.g. data-scope="profile". The wallet only ever
    // SHOWS a consent toggle for these — claims are self-asserted and may be absent.
    scope: override.scope || d.scope || '',
  };
}

// Parse a "profile" / "profile,email" scope string into a clean array of tokens.
const parseScope = (raw) =>
  String(raw || '')
    .split(/[\s,]+/)
    .filter(Boolean);

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
  const clearTimers = () => {
    timers.forEach(clearInterval);
    timers.forEach(clearTimeout);
    timers = [];
  };
  const close = () => {
    clearTimers();
    document.body.style.overflow = prevOverflow;
    host.remove();
  };
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) close();
  });

  // Organize by DEVICE, not method: on desktop the wallet is usually on a *phone*, so the QR is the
  // hero; on mobile you can't scan your own screen, so the on-device "Open the kunji app" is the hero
  // and the QR is a demoted disclosure (for a rare second device).
  const isDesktop = window.matchMedia('(min-width:640px)').matches;
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
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          audience: opts.audience,
          callbackUrl: opts.callbackUrl,
          appName: opts.appName,
        }),
      });
      if (!r.ok) throw new Error('session');
      session = await r.json(); // { sessionId, challenge, code?, expiresAt }
      currentSessionId = session.sessionId;
    } catch {
      sheet.innerHTML = `<div class="note">Couldn't start sign-in.<br><button class="again">Try again</button></div>`;
      sheet.querySelector('.again').onclick = start;
      return;
    }

    const scope = parseScope(opts.scope);
    // Full payload — rides the same-device deep link, where length is free.
    const payload = {
      kunjiAuth: 'v2',
      mode: 'discoverable',
      sessionId: session.sessionId,
      challenge: session.challenge,
      audience: opts.audience,
      callbackUrl: opts.callbackUrl,
      appName: opts.appName,
      expiresAt: session.expiresAt,
      returnUrl: location.href,
    };
    if (scope.length) payload.scope = scope;

    // Lean QR payload — drop returnUrl + mode (the wallet defaults mode), and omit callbackUrl
    // when it's the derived default (https://{audience}/kunji/callback) so the QR stays small.
    // A custom/decoupled callback (localhost dev, the relay) is kept. Keeps the QR scannable.
    const qrPayload = {
      kunjiAuth: 'v2',
      sessionId: session.sessionId,
      challenge: session.challenge,
      audience: opts.audience,
      appName: opts.appName,
      expiresAt: session.expiresAt,
    };
    if (scope.length) qrPayload.scope = scope;
    if (opts.callbackUrl !== `https://${opts.audience}/kunji/callback`) {
      qrPayload.callbackUrl = opts.callbackUrl;
    }
    // Compact "K1" encoding → an all-uppercase-alphanumeric string, so the QR renders in the denser
    // alphanumeric mode (see src/lib/qrCodec.js). The wallet accepts both K1 and JSON. The same-device
    // deep link below keeps the full JSON payload (length is free there).
    const qrData = encodeCompactQr(qrPayload);

    // Only ever build the deep link against an https wallet URL — reject
    // javascript:/data:/http: so a hostile data-app-url can't inject a scheme.
    const safeAppUrl = /^https:\/\//i.test(opts.appUrl) ? opts.appUrl : APP_URL_DEFAULT;
    const deepLink = `${safeAppUrl}/?approve=${b64url(JSON.stringify(payload))}`;

    // Everything expired together — replace the panel with one clear action so a
    // stale QR / code / deep link is never left looking usable.
    function renderExpired() {
      sheet.innerHTML = `
        <div class="top">
          <div class="title"><span class="mark">${KEY_SVG}</span> Sign in with kunji</div>
          <button class="x" aria-label="Close">×</button>
        </div>
        <div class="panel expired">
          <p>This sign-in code expired.<br>Codes are short-lived for your security.</p>
          <button class="again">Get a new code</button>
        </div>`;
      sheet.querySelector('.x').onclick = close;
      sheet.querySelector('.again').onclick = start;
    }

    // The typed-code fallback is LAZY: shown as a "Use a code" button, and the 6-digit code is only
    // revealed (or minted via opts.codeUrl) when the user clicks it — so the QR-majority never mints one.
    // `hasCode` = an eager RP already returned it (reveal instantly, no network); else opts.codeUrl mints
    // it on demand. If neither, no button (QR / deep link only).
    const hasCode = /^\d{4,10}$/.test(session.code || '');
    const canCode = hasCode || !!opts.codeUrl;
    const fmt = (c) => `${c.slice(0, 3)} ${c.slice(3)}`;

    // Reveal (eager RP) or lazily mint (opts.codeUrl) the code in place, without re-rendering the sheet.
    function wireCodeSlot() {
      const slot = sheet.querySelector('.codeslot');
      const btn = slot && slot.querySelector('.usecode');
      if (!btn) return;
      const line = (html) => (slot.innerHTML = `<p class="codehint${isDesktop ? '' : ' center'}">${html}</p>`);
      btn.onclick = async () => {
        if (hasCode) return line(`Enter code <b>${fmt(session.code)}</b> in the app.`);
        line('Getting a code…');
        try {
          const r = await fetch(opts.codeUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: currentSessionId }),
          });
          const j = await r.json().catch(() => ({}));
          if (!r.ok || !/^\d{4,10}$/.test(j.code || '')) throw new Error('nocode');
          line(`Enter code <b>${fmt(j.code)}</b> in the app.`);
        } catch {
          line('Couldn’t get a code — use the QR or the button above.');
        }
      };
    }

    render();
    function render() {
      // The branded QR + its scan caption (shared by both layouts).
      const qrBlock = `
        <div class="qrbox"></div>
        <p class="cap">Scan with the kunji app${isDesktop ? ' on your phone' : ' from another device'}.</p>`;
      const codeSlot = canCode
        ? `<div class="codeslot${isDesktop ? '' : ' center'}"><button class="usecode" type="button">Can't scan? Use a code</button></div>`
        : '';
      // Desktop: the wallet is usually on a phone → the QR is the hero; "this device" is the secondary path.
      const desktop = `
        <div class="sect">On another device</div>
        <div class="panel">
          ${qrBlock}
          ${codeSlot}
        </div>
        <div class="sect">On this device</div>
        <a class="open secondary" href="${deepLink}"><span class="mark">${KEY_SVG}</span> Open the kunji app</a>`;
      // Mobile: you can't scan your own screen → the on-device action is the hero; the QR is a disclosure.
      const mobile = `
        <a class="open" href="${deepLink}"><span class="mark">${KEY_SVG}</span> Open the kunji app</a>
        ${codeSlot}
        <details class="qrdisc">
          <summary>Show QR for another device</summary>
          <div class="panel">${qrBlock}</div>
        </details>`;
      sheet.innerHTML = `
        <div class="top">
          <div class="title"><span class="mark">${KEY_SVG}</span> Sign in with kunji</div>
          <button class="x" aria-label="Close">×</button>
        </div>
        <p class="lead">Sign in to <b>${esc(opts.appName)}</b> — no password, no account.</p>
        ${isDesktop ? desktop : mobile}
        <p class="expiry"></p>`;

      sheet.querySelector('.x').onclick = close;
      const box = sheet.querySelector('.qrbox');
      if (box) renderBrandedQr(box, { data: qrData }); // shared styled QR + amber logo plate (renders even inside the collapsed <details>)
      wireCodeSlot();

      // countdown (pauses while tab hidden); on expiry offer a fresh code
      const exp = sheet.querySelector('.expiry');
      const tick = () => {
        if (document.hidden) return;
        const left = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
        if (left <= 0) {
          clearTimers();
          renderExpired();
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
        const r = await fetch(
          `${opts.pollUrl}${opts.pollUrl.includes('?') ? '&' : '?'}sessionId=${encodeURIComponent(session.sessionId)}`,
        );
        if (!r.ok) return;
        const s = await r.json();
        if (s.status === 'approved') succeed(s);
      } catch {}
    };
    timers.push(setInterval(poll, POLL_MS));
  }

  start();
}

const esc = (s) =>
  String(s).replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c],
  );

// ── button rendering ────────────────────────────────────────────
function render(node, override = {}) {
  if (!node || node.__kunjiMounted) return;
  node.__kunjiMounted = true;
  const opts = readOpts(node, override);
  const root = node.attachShadow ? node.attachShadow({ mode: 'open' }) : node;
  const style = document.createElement('style');
  style.textContent = CSS;
  const btn = el(
    `<button class="btn ${opts.theme === 'dark' ? 'dark' : ''}"><span class="mark">${KEY_SVG}</span>${esc(opts.label)}</button>`,
  );
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
  render: (elOrSel, opts) =>
    render(typeof elOrSel === 'string' ? document.querySelector(elOrSel) : elOrSel, opts),
  signIn: (opts) => openModal(readOpts(null, opts || {}), null),
  init,
  // Render the default pseudonymous identity (name + identicon) for a `sub` you
  // received. Returns { name, avatarSvg, avatarDataUri }. Deterministic + offline —
  // use it when the user has not shared a custom profile (no `claims`).
  handle: (sub) => deriveHandle(sub),
};
