import React, { useState, useEffect, useRef, useCallback } from 'react';
import QRCode from 'qrcode';
import { doc, onSnapshot } from 'firebase/firestore';
import { db } from './firebase.js';

// The RP's identity. In production this is your real domain, hardcoded server-side.
// Here it's the current origin (audience = hostname; callback is same-site via Hosting rewrite).
const AUDIENCE = window.location.hostname;
const CALLBACK_URL = `${window.location.origin}/kunji/callback`;
const APP_NAME = 'Kunji Demo';
const KUNJI_APP_URL = 'https://app.kunji.cc';

// base64url so it rides safely in a URL query param.
const b64url = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Same-device login navigates this tab away to the wallet; persist the pending
// session id so we can resume (not restart) it when the user returns.
const RESUME_KEY = 'kunji_demo_pending';

// The kunji key mark, for the official "Sign in with kunji" button.
const KeyMark = () => (
  <svg viewBox="0 0 512 512" width="17" height="17" aria-hidden="true">
    <g transform="rotate(-40 256 256)" fill="none" stroke="currentColor" strokeWidth="58" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="240" cy="172" r="56" />
      <path d="M240 172 V398" />
      <path d="M240 334 L300 314" />
      <path d="M240 334 L300 358" />
    </g>
  </svg>
);

const STATUS = {
  loading:  { color: 'text-accent',  label: 'Generating code…' },
  scanning: { color: 'text-muted',   label: 'Scan with the kunji app' },
  resuming: { color: 'text-accent',  label: 'Finishing sign-in…' },
  approved: { color: 'text-success', label: 'Verified! Signing you in…' },
  expired:  { color: 'text-accent',  label: 'Code expired.' },
  error:    { color: 'text-danger',  label: 'Something went wrong.' },
};

export default function LoginPage({ onSuccess }) {
  const [status, setStatus] = useState('loading');
  const [secondsLeft, setSeconds] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [deepLink, setDeepLink] = useState('');
  const [code, setCode] = useState('');
  const [qrUrl, setQrUrl] = useState('');
  // Show one method at a time; default to the one that fits the device.
  const [tab, setTab] = useState(() => (window.matchMedia('(min-width: 640px)').matches ? 'qr' : 'otp'));
  const unsubRef = useRef(null);
  const timerRef = useRef(null);
  const fallbackRef = useRef(null);
  const sessionIdRef = useRef(null);

  const stop = () => {
    if (unsubRef.current) { unsubRef.current(); unsubRef.current = null; }
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    if (fallbackRef.current) { clearTimeout(fallbackRef.current); fallbackRef.current = null; }
  };

  const succeed = (sub) => {
    stop();
    localStorage.removeItem(RESUME_KEY);
    setStatus('approved');
    setTimeout(() => onSuccess({ sub }), 700);
  };

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

      // 2. Build the v2 discoverable payload — one shape, two transports (QR + deep link).
      const payload = {
        kunjiAuth: 'v2', mode: 'discoverable', sessionId, challenge,
        audience: AUDIENCE, callbackUrl: CALLBACK_URL, appName: APP_NAME, expiresAt,
        returnUrl: window.location.href,
      };
      const qrData = JSON.stringify(payload);
      setQrUrl(await QRCode.toDataURL(qrData, { width: 200, margin: 1, color: { dark: '#1a1a18', light: '#ffffff' } }));
      setDeepLink(`${KUNJI_APP_URL}/?approve=${b64url(qrData)}`); // same-device: open kunji directly
      setStatus('scanning');

      // Countdown — pauses while the tab is hidden; on expiry we stop and show a
      // "Show new code" button (one cycle) instead of auto-reminting forever.
      const tick = () => {
        if (document.hidden) return; // pause when not looking
        const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
        setSeconds(left);
        if (left === 0) { stop(); setStatus('expired'); }
      };
      tick();
      timerRef.current = setInterval(tick, 1000);

      // 3. Listen to our session doc — flips to signed-in the instant the wallet approves.
      unsubRef.current = onSnapshot(doc(db, 'loginSessions', sessionId), (snap) => {
        if (snap.data()?.status === 'approved') succeed(snap.data().sub);
      });
    } catch (err) {
      setStatus('error');
      setErrorMsg(err.message || 'Failed to start login.');
    }
  }, [onSuccess]);

  // Same-device return: resume the saved session instead of starting a new one.
  const resumeFlow = useCallback((savedId) => {
    stop();
    setStatus('resuming');
    unsubRef.current = onSnapshot(doc(db, 'loginSessions', savedId), (snap) => {
      if (snap.data()?.status === 'approved') succeed(snap.data().sub);
    });
    // If it wasn't approved (cancelled / gone), fall back to a fresh QR.
    fallbackRef.current = setTimeout(() => {
      localStorage.removeItem(RESUME_KEY);
      startFlow();
    }, 9000);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [startFlow]);

  useEffect(() => {
    // Resume only if we navigated out via "Open kunji" (one-shot: read + clear).
    const consumeResume = () => {
      const id = localStorage.getItem(RESUME_KEY);
      if (id) localStorage.removeItem(RESUME_KEY);
      return id;
    };

    const saved = consumeResume();
    if (saved) resumeFlow(saved); else startFlow();

    // If the page is restored from bfcache (e.g. back button) after Open kunji.
    const onPageShow = (e) => {
      if (!e.persisted) return;
      const id = consumeResume();
      if (id) resumeFlow(id);
    };
    window.addEventListener('pageshow', onPageShow);
    return () => { window.removeEventListener('pageshow', onPageShow); stop(); };
  }, [startFlow, resumeFlow]);

  const meta = STATUS[status] || STATUS.loading;

  const tabBtn = (id, label) =>
    <button
      onClick={() => setTab(id)}
      className={`pb-2 text-sm font-medium border-b-2 -mb-px transition-colors rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
        tab === id ? 'border-accent text-ink' : 'border-transparent text-faint hover:text-muted'
      }`}
    >{label}</button>;

  return (
    <>
      <header className="flex items-center gap-2 max-w-[26rem] w-full mx-auto px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <span className="text-[15px] font-medium text-faint">Kunji Demo</span>
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
            <button onClick={startFlow}
              className="inline-flex items-center justify-center px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors">
              Show new code
            </button>
          </div>
        ) : status === 'error' ? (
          <div>
            <p className="text-[15px] text-danger mb-6">{errorMsg || 'Something went wrong.'}</p>
            <button onClick={startFlow}
              className="inline-flex items-center justify-center px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity">
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
                  <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-2">Type this code into kunji</p>
                  <div className="font-mono tabular text-4xl tracking-[0.2em] text-ink">
                    {code.slice(0, 3)} {code.slice(3)}
                  </div>
                  <p className="text-[13px] text-muted mt-3">Open kunji → enter this code.</p>
                </div>
              ) : (
                <div>
                  <div className="inline-block rounded-2xl border border-line p-4 bg-surface">
                    {qrUrl && <img src={qrUrl} alt="Sign-in QR" className="w-[200px] h-[200px]" />}
                  </div>
                  <p className="text-[13px] text-muted mt-4">Scan with the kunji app on your phone.</p>
                </div>
              )}
            </div>

            {/* same-device action — the canonical branded button, available under both tabs */}
            <div className="flex items-center gap-3 text-[11px] uppercase tracking-[0.14em] text-faint my-5">
              <span className="flex-1 h-px bg-line" /> on this device <span className="flex-1 h-px bg-line" />
            </div>
            <a
              href={deepLink}
              onClick={() => localStorage.setItem(RESUME_KEY, sessionIdRef.current || '')}
              className="inline-flex items-center justify-center gap-2 w-full px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
            >
              <KeyMark /> Sign in with kunji
            </a>

            {secondsLeft > 0 && (
              <p className="text-[12px] text-faint mt-6 text-center">Expires in <span className="font-mono tabular">{secondsLeft}s</span></p>
            )}
          </>
        )}
        </div>
      </main>
    </>
  );
}
