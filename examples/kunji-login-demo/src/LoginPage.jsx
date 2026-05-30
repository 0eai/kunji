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
  const [qrUrl, setQrUrl] = useState('');
  // Show one method at a time; default to the one that fits the device.
  const [tab, setTab] = useState(() => (window.matchMedia('(min-width: 640px)').matches ? 'qr' : 'device'));
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
      setQrUrl(await QRCode.toDataURL(qrData, { width: 200, margin: 1, color: { dark: '#1c1606', light: '#fbbf24' } }));
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
      className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-colors ${tab === id ? 'bg-amber-500 text-black' : 'text-gray-400 hover:text-white'}`}
    >{label}</button>;

  return (
    <div className="bg-[#18140c] border border-[#2a2316] rounded-3xl p-6 max-w-sm w-full text-center">
      <div className="mb-4">
        <img src="/icon.svg" alt="kunji" className="w-11 h-11 rounded-xl mx-auto mb-2" />
        <h1 className="text-xl font-bold">Sign in with kunji</h1>
      </div>

      {status === 'approved' ? (
        <div className="flex flex-col items-center gap-2 py-6">
          <div className="w-14 h-14 bg-green-500/15 rounded-full flex items-center justify-center">
            <svg className="w-8 h-8 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 13l4 4L19 7"/></svg>
          </div>
          <p className="text-sm font-medium text-green-400">Signing you in…</p>
        </div>
      ) : status === 'expired' ? (
        <div className="py-4">
          <p className="text-sm text-amber-400 mb-4">Code expired.</p>
          <button onClick={startFlow} className="w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors">
            Show new code
          </button>
        </div>
      ) : status === 'error' ? (
        <div className="py-4">
          <p className="text-sm text-red-400">{errorMsg || 'Something went wrong.'}</p>
          <button onClick={startFlow} className="mt-4 w-full py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-semibold transition-colors">Try again</button>
        </div>
      ) : status !== 'scanning' ? (
        <p className={`text-sm font-medium ${meta.color} py-8`}>{meta.label}</p>
      ) : (
        <>
          {/* Method toggle */}
          <div className="flex gap-1 p-1 rounded-xl bg-black/40 border border-[#2a2316] mb-4">
            {tabBtn('device', 'This device')}
            {tabBtn('qr', 'Another device')}
          </div>

          {tab === 'device' ? (
            <div>
              <a
                href={deepLink}
                onClick={() => localStorage.setItem(RESUME_KEY, sessionIdRef.current || '')}
                className="block w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors"
              >
                Open kunji
              </a>
              {code && (
                <div className="mt-4">
                  <p className="text-xs text-gray-500 mb-1">Or type this code in kunji</p>
                  <div className="font-mono text-3xl tracking-[0.25em] text-amber-300 font-bold">
                    {code.slice(0, 3)} {code.slice(3)}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center">
              {qrUrl && <img src={qrUrl} alt="Sign-in QR" className="w-[200px] h-[200px] rounded-xl border-2 border-amber-500/40" />}
              <p className="text-xs text-gray-500 mt-3">Scan with the kunji app on your phone</p>
            </div>
          )}

          {secondsLeft > 0 && (
            <p className="text-xs text-gray-600 mt-3">Expires in <span className="font-mono">{secondsLeft}s</span></p>
          )}
        </>
      )}
    </div>
  );
}
