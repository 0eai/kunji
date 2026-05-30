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

const STATUS = {
  loading:  { color: 'text-amber-400', label: 'Generating QR…' },
  scanning: { color: 'text-gray-400', label: 'Scan with the kunji app' },
  resuming: { color: 'text-amber-400', label: 'Finishing sign-in…' },
  approved: { color: 'text-green-400', label: 'Verified! Signing you in…' },
  expired:  { color: 'text-amber-400', label: 'Code expired.' },
  error:    { color: 'text-red-400',   label: 'Something went wrong.' },
};

export default function LoginPage({ onSuccess }) {
  const [status, setStatus] = useState('loading');
  const [secondsLeft, setSeconds] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [deepLink, setDeepLink] = useState('');
  const [code, setCode] = useState('');
  const canvasRef = useRef(null);
  const unsubRef = useRef(null);
  const timerRef = useRef(null);
  const fallbackRef = useRef(null);

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
      localStorage.setItem(RESUME_KEY, sessionId); // resume this on same-device return

      // 2. Build the v2 discoverable payload — one shape, two transports (QR + deep link).
      const payload = {
        kunjiAuth: 'v2', mode: 'discoverable', sessionId, challenge,
        audience: AUDIENCE, callbackUrl: CALLBACK_URL, appName: APP_NAME, expiresAt,
        returnUrl: window.location.href,
      };
      const qrData = JSON.stringify(payload);
      await QRCode.toCanvas(canvasRef.current, qrData, { width: 240, margin: 1, color: { dark: '#1c1606', light: '#fbbf24' } });
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
    const saved = localStorage.getItem(RESUME_KEY);
    if (saved) resumeFlow(saved); else startFlow();

    // If the page is restored from bfcache (e.g. back button), re-check the saved session.
    const onPageShow = (e) => {
      if (!e.persisted) return;
      const id = localStorage.getItem(RESUME_KEY);
      if (id) resumeFlow(id);
    };
    window.addEventListener('pageshow', onPageShow);
    return () => { window.removeEventListener('pageshow', onPageShow); stop(); };
  }, [startFlow, resumeFlow]);

  const meta = STATUS[status] || STATUS.loading;

  return (
    <div className="bg-[#18140c] border border-[#2a2316] rounded-3xl p-8 max-w-sm w-full text-center">
      <div className="mb-6">
        <img src="/icon.svg" alt="kunji" className="w-12 h-12 rounded-xl mx-auto mb-3" />
        <h1 className="text-2xl font-bold">Sign in</h1>
        <p className="text-gray-500 text-sm mt-1">with kunji</p>
      </div>

      <div className="relative flex items-center justify-center mb-5">
        <div className={`rounded-2xl overflow-hidden border-2 transition-all ${status === 'scanning' ? 'border-amber-500/40' : 'border-[#2a2316]'}`}>
          <canvas ref={canvasRef} className={`block transition-opacity ${status === 'scanning' ? 'opacity-100' : 'opacity-30'}`} />
        </div>
        {status === 'approved' && (
          <div className="absolute inset-0 flex items-center justify-center rounded-2xl bg-[#18140c]/85">
            <div className="w-14 h-14 bg-green-500/15 rounded-full flex items-center justify-center">
              <svg className="w-8 h-8 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 13l4 4L19 7"/></svg>
            </div>
          </div>
        )}
      </div>

      <p className={`text-sm font-medium ${meta.color} min-h-[20px]`}>
        {meta.label}
        {errorMsg && <span className="block mt-1 text-xs text-red-400">{errorMsg}</span>}
      </p>

      {status === 'scanning' && secondsLeft > 0 && (
        <p className="text-xs text-gray-500 mt-2">Expires in <span className="font-mono">{secondsLeft}s</span></p>
      )}

      {status === 'scanning' && deepLink && (
        <>
          <div className="flex items-center gap-3 my-4">
            <div className="flex-1 h-px bg-[#2a2316]" />
            <span className="text-[11px] text-gray-600 uppercase tracking-wider">on this device</span>
            <div className="flex-1 h-px bg-[#2a2316]" />
          </div>
          <a
            href={deepLink}
            className="block w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors"
          >
            Open kunji
          </a>

          {code && (
            <div className="mt-4">
              <p className="text-xs text-gray-500 mb-1">Or enter this code in kunji</p>
              <div className="font-mono text-3xl tracking-[0.3em] text-amber-300 font-bold">
                {code.slice(0, 3)} {code.slice(3)}
              </div>
            </div>
          )}
          <p className="text-xs text-gray-600 mt-4">Or scan the QR from another device.</p>
        </>
      )}

      {status === 'expired' && (
        <button
          onClick={startFlow}
          className="mt-4 w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors"
        >
          Show new code
        </button>
      )}
    </div>
  );
}
