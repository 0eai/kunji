import React, { useState, useEffect, useRef, useCallback } from 'react';
import QRCode from 'qrcode';

// The RP's identity. In production this is your real domain, hardcoded server-side.
// For the local demo we use the current origin (audience = hostname, e.g. "localhost").
const AUDIENCE = window.location.hostname;
const CALLBACK_URL = `${window.location.origin}/kunji/callback`;
const APP_NAME = 'Kunji Demo';

const STATUS = {
  loading:  { color: 'text-amber-400', label: 'Generating QR…' },
  scanning: { color: 'text-gray-400', label: 'Scan with the kunji app' },
  approved: { color: 'text-green-400', label: 'Verified! Signing you in…' },
  expired:  { color: 'text-amber-400', label: 'QR expired. Refreshing…' },
  error:    { color: 'text-red-400',   label: 'Something went wrong.' },
};

export default function LoginPage({ onSuccess }) {
  const [status, setStatus] = useState('loading');
  const [secondsLeft, setSeconds] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const canvasRef = useRef(null);
  const pollRef = useRef(null);
  const timerRef = useRef(null);

  const stop = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
  };

  const startFlow = useCallback(async () => {
    stop();
    setStatus('loading');
    setErrorMsg('');
    try {
      // 1. Ask our own backend to create a session.
      const resp = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ audience: AUDIENCE, callbackUrl: CALLBACK_URL, appName: APP_NAME }),
      });
      const { sessionId, challenge, expiresAt } = await resp.json();

      // 2. Build the v2 discoverable QR and render it.
      const qrData = JSON.stringify({
        kunjiAuth: 'v2',
        mode: 'discoverable',
        sessionId,
        challenge,
        audience: AUDIENCE,
        callbackUrl: CALLBACK_URL,
        appName: APP_NAME,
        expiresAt,
      });
      await QRCode.toCanvas(canvasRef.current, qrData, {
        width: 240, margin: 1, color: { dark: '#1c1606', light: '#fbbf24' },
      });
      setStatus('scanning');

      // Countdown
      const tick = () => setSeconds(Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000)));
      tick();
      timerRef.current = setInterval(tick, 1000);

      // 3. Poll our backend for the verified result.
      pollRef.current = setInterval(async () => {
        const r = await fetch(`/api/session/${sessionId}`).then(x => x.json()).catch(() => ({}));
        if (r.status === 'approved') {
          stop();
          setStatus('approved');
          setTimeout(() => onSuccess({ sub: r.sub }), 700);
        } else if (r.status === 'expired' || r.status === 'unknown') {
          stop();
          setStatus('expired');
          setTimeout(startFlow, 1000);
        }
      }, 1500);
    } catch (err) {
      setStatus('error');
      setErrorMsg(err.message || 'Failed to start login.');
    }
  }, [onSuccess]);

  useEffect(() => { startFlow(); return stop; }, [startFlow]);

  const meta = STATUS[status] || STATUS.loading;

  return (
    <div className="bg-[#18140c] border border-[#2a2316] rounded-3xl p-8 max-w-sm w-full text-center">
      <div className="mb-6">
        <div className="w-12 h-12 bg-amber-500 rounded-xl flex items-center justify-center mx-auto mb-3">
          <svg className="w-6 h-6 text-black" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 21 2m-5 3 3 3m-6-6 3 3"/></svg>
        </div>
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
      {status === 'scanning' && (
        <p className="text-xs text-gray-600 mt-5">Open <strong className="text-gray-400">kunji</strong> → tap <strong className="text-gray-400">Scan QR</strong></p>
      )}
    </div>
  );
}
