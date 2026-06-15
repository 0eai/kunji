import React, { useState, useEffect, useRef, useCallback } from 'react';
import QRCodeStyling from 'qr-code-styling';

// The RP's identity. In production this is your real domain, hardcoded server-side.
// Here it's the current origin (audience = hostname; callback is same-site via Hosting rewrite).
const AUDIENCE = window.location.hostname;
const CALLBACK_URL = `${window.location.origin}/kunji/callback`;
const APP_NAME = 'kunji demo';
const KUNJI_APP_URL = 'https://app.kunji.cc';

// Brand-styled QR: extra-rounded modules + the kunji app-icon logo (amber tile + dark key),
// centered with a cleared quiet area. Pure presentation — `data` is the QR payload unchanged.
const APP_ICON =
  'data:image/svg+xml,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">' +
      '<rect width="512" height="512" rx="116" fill="#f59e0b"/>' +
      '<g transform="rotate(-40 256 256)" fill="none" stroke="#1c1606" stroke-width="58" stroke-linecap="round" stroke-linejoin="round">' +
      '<circle cx="240" cy="172" r="56" fill="#1c1606"/>' +
      '<path d="M240 172 V398"/><path d="M240 334 L300 314"/><path d="M240 334 L300 358"/>' +
      '</g></svg>',
  );
// Canonical branded QR — mirror of the wallet's src/lib/brandedQr.js (separate bundle → copy, not
// import). Overlay the amber logo as an <img> (img-src), not qr-code-styling's fetched `image`
// (connect-src, which a strict CSP would blank); EC 'H' covers the occluded center; margin:0 +
// the container's p-3 is the single quiet zone.
const SIZE = 224;
const renderBrandedQr = (el, data) => {
  if (!el || !data) return;
  const qr = new QRCodeStyling({
    type: 'svg',
    width: SIZE,
    height: SIZE,
    data,
    margin: 0,
    qrOptions: { errorCorrectionLevel: 'H' },
    backgroundOptions: { color: '#ffffff' },
    // roundSize:false — otherwise qr-code-styling floors the dot size and centers the pattern,
    // baking a payload-length-dependent white margin inside the svg. Mirror of src/lib/brandedQr.js.
    dotsOptions: { type: 'extra-rounded', color: '#1a1a18', roundSize: false },
    cornersSquareOptions: { type: 'extra-rounded', color: '#1a1a18' },
    cornersDotOptions: { color: '#1a1a18' },
  });
  el.replaceChildren();
  qr.append(el);
  // Pin the SVG to exactly SIZE + display:block so framing matches the wallet/widget pixel-for-pixel.
  const svg = el.querySelector('svg');
  if (svg) svg.style.cssText = `display:block;width:${SIZE}px;height:${SIZE}px`;
  el.style.position = 'relative';
  const logo = document.createElement('img');
  logo.src = APP_ICON;
  logo.alt = '';
  // The amber tile on a generous white squircle = a cleared quiet zone, so the logo floats clear of
  // the modules. Mirror of src/lib/brandedQr.js — keep byte-equal. EC 'H' covers what it occludes.
  const halo = Math.round(SIZE * 0.05); // ~11px white border on each side
  const plate = Math.round(SIZE * 0.21) + halo * 2; // amber tile ~47px + the halo
  const radius = Math.round(SIZE * 0.085); // ~19px squircle
  logo.style.cssText = `position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:${plate}px;height:${plate}px;padding:${halo}px;background:#fff;border-radius:${radius}px;box-sizing:border-box`;
  el.appendChild(logo);
};

// base64url so it rides safely in a URL query param.
const b64url = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Same-device login navigates this tab away to the wallet; persist the pending
// session id so we can resume (not restart) it when the user returns.
const RESUME_KEY = 'kunji_demo_pending';

// The kunji key mark, for the official "Sign in with kunji" button.
const KeyMark = () => (
  <svg viewBox="0 0 512 512" width="17" height="17" aria-hidden="true">
    <g
      transform="rotate(-40 256 256)"
      fill="none"
      stroke="currentColor"
      strokeWidth="58"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="240" cy="172" r="56" fill="currentColor" />
      <path d="M240 172 V398" />
      <path d="M240 334 L300 314" />
      <path d="M240 334 L300 358" />
    </g>
  </svg>
);

const STATUS = {
  loading: { color: 'text-accent', label: 'Generating code…' },
  scanning: { color: 'text-muted', label: 'Scan with the kunji app' },
  resuming: { color: 'text-accent', label: 'Finishing sign-in…' },
  approved: { color: 'text-success', label: 'Verified! Signing you in…' },
  expired: { color: 'text-accent', label: 'Code expired.' },
  error: { color: 'text-danger', label: 'Something went wrong.' },
};

export default function LoginPage({ onSuccess }) {
  const [status, setStatus] = useState('loading');
  const [secondsLeft, setSeconds] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [deepLink, setDeepLink] = useState('');
  const [code, setCode] = useState('');
  const [qrData, setQrData] = useState('');
  const qrRef = useRef(null);
  // Show one method at a time; default to the one that fits the device.
  const [tab, setTab] = useState(() =>
    window.matchMedia('(min-width: 640px)').matches ? 'qr' : 'otp',
  );
  const unsubRef = useRef(null);

  // Render the styled QR when we have a payload and the QR tab is visible (so switching
  // tabs re-renders into the freshly-mounted container).
  useEffect(() => {
    if (tab === 'qr' && qrData) renderBrandedQr(qrRef.current, qrData);
  }, [tab, qrData]);
  const timerRef = useRef(null);
  const fallbackRef = useRef(null);
  const sessionIdRef = useRef(null);

  const stop = useCallback(() => {
    if (unsubRef.current) {
      unsubRef.current();
      unsubRef.current = null;
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (fallbackRef.current) {
      clearTimeout(fallbackRef.current);
      fallbackRef.current = null;
    }
  }, []);

  const succeed = useCallback(
    (sub, claims) => {
      stop();
      localStorage.removeItem(RESUME_KEY);
      setStatus('approved');
      setTimeout(() => onSuccess({ sub, claims: claims || null }), 700);
    },
    [stop, onSuccess],
  );

  // Poll our own backend for approval. loginSessions is server-only (the demo no
  // longer reads Firestore directly); we hit the getSessionStatus function instead.
  // Returns a cleanup fn so stop() can cancel it like the old onSnapshot unsubscribe.
  const pollStatus = useCallback(
    (sessionId) => {
      const check = async () => {
        if (document.hidden) return;
        try {
          const r = await fetch(`/kunji/status?sessionId=${encodeURIComponent(sessionId)}`);
          if (!r.ok) return;
          const s = await r.json();
          if (s.status === 'approved') succeed(s.sub, s.claims);
        } catch {
          /* transient */
        }
      };
      check();
      const id = setInterval(check, 2000);
      return () => clearInterval(id);
    },
    [succeed],
  );

  const startFlow = useCallback(async () => {
    stop();
    setStatus('loading');
    setErrorMsg('');
    try {
      // 1. Ask our own backend (Function) to create a session.
      const resp = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ audience: AUDIENCE, callbackUrl: CALLBACK_URL, appName: APP_NAME }),
      });
      if (!resp.ok) throw new Error('createSession failed');
      const { sessionId, challenge, code, expiresAt } = await resp.json();
      setCode(code || '');
      sessionIdRef.current = sessionId; // stashed for RESUME_KEY only when "Open kunji" is tapped

      // 2. Build the v2 discoverable payload. The full payload (with returnUrl) rides the
      //    same-device deep link; a LEAN payload powers the QR (drop returnUrl + mode, and
      //    omit callbackUrl when it's the derived default) so the QR stays low-density.
      const payload = {
        kunjiAuth: 'v2',
        mode: 'discoverable',
        sessionId,
        challenge,
        audience: AUDIENCE,
        callbackUrl: CALLBACK_URL,
        appName: APP_NAME,
        expiresAt,
        returnUrl: window.location.href,
        // Ask kunji to OFFER sharing a profile. The user may decline — claims are
        // optional, so we always fall back to the default identity derived from `sub`.
        scope: ['profile'],
      };
      const qrPayload = {
        kunjiAuth: 'v2',
        sessionId,
        challenge,
        audience: AUDIENCE,
        appName: APP_NAME,
        expiresAt,
        scope: ['profile'],
      };
      if (CALLBACK_URL !== `https://${AUDIENCE}/kunji/callback`) qrPayload.callbackUrl = CALLBACK_URL;
      setQrData(JSON.stringify(qrPayload));
      setDeepLink(`${KUNJI_APP_URL}/?approve=${b64url(JSON.stringify(payload))}`); // same-device: open kunji directly
      setStatus('scanning');

      // Countdown — pauses while the tab is hidden; on expiry we stop and show a
      // "Show new code" button (one cycle) instead of auto-reminting forever.
      const tick = () => {
        if (document.hidden) return; // pause when not looking
        const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
        setSeconds(left);
        if (left === 0) {
          stop();
          setStatus('expired');
        }
      };
      tick();
      timerRef.current = setInterval(tick, 1000);

      // 3. Poll our backend — flips to signed-in once the wallet approves.
      unsubRef.current = pollStatus(sessionId);
    } catch (err) {
      setStatus('error');
      setErrorMsg(err.message || 'Failed to start login.');
    }
  }, [stop, pollStatus]);

  // Same-device return: resume the saved session instead of starting a new one.
  const resumeFlow = useCallback(
    (savedId) => {
      stop();
      setStatus('resuming');
      unsubRef.current = pollStatus(savedId);
      // If it wasn't approved (cancelled / gone), fall back to a fresh QR.
      fallbackRef.current = setTimeout(() => {
        localStorage.removeItem(RESUME_KEY);
        startFlow();
      }, 9000);
    },
    [stop, pollStatus, startFlow],
  );

  useEffect(() => {
    // Resume only if we navigated out via "Open kunji" (one-shot: read + clear).
    const consumeResume = () => {
      const id = localStorage.getItem(RESUME_KEY);
      if (id) localStorage.removeItem(RESUME_KEY);
      return id;
    };

    const saved = consumeResume();
    if (saved) resumeFlow(saved);
    else startFlow();

    // If the page is restored from bfcache (e.g. back button) after Open kunji.
    const onPageShow = (e) => {
      if (!e.persisted) return;
      const id = consumeResume();
      if (id) resumeFlow(id);
    };
    window.addEventListener('pageshow', onPageShow);
    return () => {
      window.removeEventListener('pageshow', onPageShow);
      stop();
    };
  }, [startFlow, resumeFlow, stop]);

  const meta = STATUS[status] || STATUS.loading;

  const tabBtn = (id, label) => (
    <button
      onClick={() => setTab(id)}
      className={`pb-2 text-sm font-medium border-b-2 -mb-px transition-colors rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
        tab === id ? 'border-accent text-ink' : 'border-transparent text-faint hover:text-muted'
      }`}
    >
      {label}
    </button>
  );

  return (
    <>
      <header className="flex items-center gap-2 max-w-[26rem] w-full mx-auto px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · sign in</span>
        <a
          href="#"
          className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline"
        >
          ← demos
        </a>
      </header>

      <main className="flex-1 flex flex-col justify-center max-w-[26rem] w-full mx-auto px-6 animate-rise">
        <div className="mb-9">
          <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Sign in</h1>
          <p className="text-[15px] text-muted mt-1">with kunji — no password, no account.</p>
        </div>

        {/* constant-height region so switching tabs / states never moves the heading */}
        <div className="min-h-[24rem]">
          {status === 'approved' ? (
            <p className="text-[15px] font-medium text-success py-6">Verified — signing you in…</p>
          ) : status === 'expired' ? (
            <div>
              <p className="text-[15px] text-accent mb-6">Code expired.</p>
              <button
                onClick={startFlow}
                className="inline-flex items-center justify-center px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
              >
                Show new code
              </button>
            </div>
          ) : status === 'error' ? (
            <div>
              <p className="text-[15px] text-danger mb-6">{errorMsg || 'Something went wrong.'}</p>
              <button
                onClick={startFlow}
                className="inline-flex items-center justify-center px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity"
              >
                Try again
              </button>
            </div>
          ) : status !== 'scanning' ? (
            <p className={`text-[15px] font-medium ${meta.color} py-6`}>{meta.label}</p>
          ) : (
            <>
              {/* Method toggle — text tabs with amber underline */}
              <div className="flex gap-6 border-b border-line mb-7">
                {tabBtn('qr', 'QR')}
                {code && tabBtn('otp', 'OTP')}
              </div>

              {/* fixed-height panel so switching QR↔OTP never resizes the page */}
              <div className="min-h-[17rem]">
                {tab === 'otp' && code ? (
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-2">
                      Type this code into kunji
                    </p>
                    <div className="font-mono tabular text-4xl tracking-[0.2em] text-ink">
                      {code.slice(0, 3)} {code.slice(3)}
                    </div>
                    <p className="text-[13px] text-muted mt-3">Open kunji → enter this code.</p>
                  </div>
                ) : (
                  <div>
                    <div
                      ref={qrRef}
                      className="relative inline-flex rounded-2xl border border-line bg-white p-3"
                    />
                    <p className="text-[13px] text-muted mt-4">
                      Scan with the kunji app on your phone.
                    </p>
                  </div>
                )}
              </div>

              {/* same-device action — the canonical branded button, available under both tabs */}
              <div className="flex items-center gap-3 text-[11px] uppercase tracking-[0.14em] text-faint my-5">
                <span className="flex-1 h-px bg-line" /> on this device{' '}
                <span className="flex-1 h-px bg-line" />
              </div>
              <a
                href={deepLink}
                onClick={() => localStorage.setItem(RESUME_KEY, sessionIdRef.current || '')}
                className="inline-flex items-center justify-center gap-2 w-full px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
              >
                <KeyMark /> Sign in with kunji
              </a>

              {secondsLeft > 0 && (
                <p className="text-[12px] text-faint mt-6 text-center">
                  Expires in <span className="font-mono tabular">{secondsLeft}s</span>
                </p>
              )}
            </>
          )}
        </div>
      </main>
    </>
  );
}
