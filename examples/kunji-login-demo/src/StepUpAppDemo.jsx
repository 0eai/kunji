import React, { useEffect, useRef, useState, useCallback } from 'react';

// APP step-up demo (push-relay.md Transport ① / scope.md §7): a regular relying party where a HUMAN signed
// in later needs more — here, a verified age. Unlike the agent #stepup (a holder-of-key capability), the app
// just re-runs "Sign in with kunji" requesting a `vc:` scope: because you already use the app, the wallet
// shows a DELTA re-consent ("you already use this app — it's also asking to prove a verified credential") and
// lets you present the credential inside the login assertion. The RP gate reads what was presented. Driven by
// the real rp.js widget (window.kunji, loaded in index.html), same endpoints as the #rpjs demo.
const APP = {
  'data-app-name': 'kunji demo',
  'data-audience': 'kunji-demo.web.app',
  'data-session-url': 'https://kunji-demo.web.app/api/session',
  'data-callback-url': 'https://kunji-demo.web.app/kunji/callback',
  'data-poll-url': 'https://kunji-demo.web.app/kunji/status',
};

const getJson = async (url) => {
  const r = await fetch(url);
  let body = {};
  try { body = await r.json(); } catch { /* non-JSON */ }
  return { status: r.status, body };
};

export default function StepUpAppDemo({ onBack }) {
  // phase: connect → gated → stepup → done | nocred
  const [phase, setPhase] = useState('connect');
  const phaseRef = useRef('connect');
  const setPhaseSync = (p) => { phaseRef.current = p; setPhase(p); };
  const [sub, setSub] = useState('');
  const [released, setReleased] = useState(null); // the 200 /api/age-gated body
  const [io, setIo] = useState(null);
  const [err, setErr] = useState('');
  const sid1 = useRef(''); // session from the connect round
  const mountRef = useRef(null);
  const resultRef = useRef(null);

  // (Re)mount the real drop-in widget with the phase's scope. Round 1 = plain login; the step-up round
  // adds vc:age_over_18 so the wallet offers to present the credential.
  const mountSignin = useCallback((scope) => {
    const mount = mountRef.current;
    if (!mount) return;
    if (!window.kunji) { setErr('rp.js failed to load.'); return; }
    mount.replaceChildren();
    const div = document.createElement('div');
    div.setAttribute('data-kunji-signin', '');
    Object.entries(APP).forEach(([k, v]) => div.setAttribute(k, v));
    if (scope) div.setAttribute('data-scope', scope);
    mount.appendChild(div);
    window.kunji.render(div);
  }, []);

  useEffect(() => {
    if (phase === 'connect') mountSignin('profile');
    else if (phase === 'stepup') mountSignin('vc:age_over_18');
  }, [phase, mountSignin]);

  useEffect(() => {
    if ((phase === 'done' || phase === 'nocred') && resultRef.current) resultRef.current.focus();
  }, [phase]);

  // One kunji:success listener; it dispatches by the current phase (read via a ref to avoid a stale closure).
  useEffect(() => {
    const onSuccess = async (e) => {
      const d = e.detail || {};
      if (phaseRef.current === 'connect') {
        sid1.current = d.sessionId;
        setSub(d.sub || '');
        setPhaseSync('gated');
      } else if (phaseRef.current === 'stepup') {
        const g = await getJson(`https://kunji-demo.web.app/api/age-gated?sessionId=${encodeURIComponent(d.sessionId)}`);
        setIo({ connectSession: sid1.current, stepupSession: d.sessionId, gated: g.body, verified: d.verified || null });
        if (g.status === 200) { setReleased(g.body); setPhaseSync('done'); }
        else setPhaseSync('nocred'); // approved but no age credential was presented
      }
    };
    document.addEventListener('kunji:success', onSuccess);
    return () => document.removeEventListener('kunji:success', onSuccess);
  }, []);

  const openGated = useCallback(async () => {
    setErr('');
    const g = await getJson(`https://kunji-demo.web.app/api/age-gated?sessionId=${encodeURIComponent(sid1.current)}`);
    if (g.status === 200) { setReleased(g.body); setPhaseSync('done'); return; } // already proven (rare)
    if (g.status === 403) setPhaseSync('stepup'); // needs the credential → step up
    else setErr(`Unexpected ${g.status} from the age-gated action.`);
  }, []);

  const reset = () => {
    setSub(''); setReleased(null); setIo(null); setErr(''); sid1.current = '';
    setPhaseSync('connect');
  };

  return (
    <main className="flex-1 flex flex-col max-w-[34rem] w-full mx-auto px-6 py-10 animate-rise">
      <header className="flex items-center gap-2 mb-8">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · app step-up</span>
        {onBack && (
          <button onClick={onBack} className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline">
            ← demos
          </button>
        )}
      </header>

      <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Ask for more after sign-in</h1>
      <p className="text-[15px] text-muted mt-1 mb-4">
        A regular app where you've signed in later needs a <b>verified fact</b>. Instead of asking up front, it{' '}
        <b>steps up</b>: it re-runs sign-in requesting your age, and the wallet shows only the <b>delta</b> to
        approve — you present the credential, never your birthday. (This is the login path + the delta consent —
        distinct from the holder-of-key{' '}
        <a href="#agentic" className="text-accent hover:text-ink underline underline-offset-2">agent</a> step-up.)
      </p>
      <p className="text-[12px] text-muted bg-accent-soft border border-line rounded-lg px-3 py-2 mb-6">
        Prereq: your wallet must hold an <b>age credential</b>. Get one first at{' '}
        <a href="#credentials" className="text-accent hover:text-ink underline underline-offset-2">#credentials</a>{' '}
        (or issuer.kunji.cc), then come back.
      </p>

      {/* Phase 1 — connect */}
      <section className="rounded-2xl border border-line p-6 mb-5">
        <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-1">Step 1 · Sign in</p>
        <h2 className="text-[1.25rem] font-semibold tracking-tight">Connect to the app</h2>
        <p className="text-[14px] text-muted mt-1 mb-4">A normal passwordless sign-in — no credential yet.</p>
        {phase === 'connect' ? (
          <div ref={mountRef} />
        ) : (
          <p className="text-[13px] text-success">✓ Signed in as <span className="font-mono text-ink break-all">{sub.slice(0, 24)}…</span></p>
        )}
      </section>

      {/* Phase 2 — the gated action */}
      {phase !== 'connect' && (
        <section className="rounded-2xl border border-line p-6 mb-5">
          <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-1">Step 2 · A gated action</p>
          <h2 className="text-[1.25rem] font-semibold tracking-tight">Enter the over-18 area</h2>
          <p className="text-[14px] text-muted mt-1 mb-4">
            The app calls <span className="font-mono text-ink">/api/age-gated</span> — released only if you've
            proven <span className="font-mono text-ink">age_over_18</span>.
          </p>
          {phase === 'gated' ? (
            <button
              onClick={openGated}
              className="inline-flex items-center justify-center px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity"
            >
              Open the over-18 area
            </button>
          ) : (
            <p className="text-[13px] text-accent">403 credential_required — the app needs your verified age.</p>
          )}
        </section>
      )}

      {/* Phase 3 — step up (re-sign-in requesting the credential) */}
      {(phase === 'stepup' || phase === 'nocred') && (
        <section className="rounded-2xl border border-line p-6 mb-5">
          <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-1">Step 3 · Step up</p>
          <h2 className="text-[1.25rem] font-semibold tracking-tight">Prove your age</h2>
          <p className="text-[14px] text-muted mt-1 mb-4">
            Sign in again — the wallet recognizes you're <b>already connected</b> and asks only to{' '}
            <b>prove a verified credential</b>. Approve it and present your age credential.
          </p>
          <div ref={mountRef} />
          {phase === 'nocred' && (
            <div ref={resultRef} tabIndex={-1} className="mt-4 rounded-xl bg-accent-soft border border-line p-4 outline-none">
              <p className="text-[14px] text-ink">
                Still locked — it looks like your wallet didn't present an age credential. Get one at{' '}
                <a href="#credentials" className="text-accent hover:text-ink underline underline-offset-2">#credentials</a>,
                then <button onClick={reset} className="text-accent hover:text-ink underline underline-offset-2">start over</button>.
              </p>
            </div>
          )}
        </section>
      )}

      {/* Phase 4 — released */}
      {phase === 'done' && released && (
        <section ref={resultRef} tabIndex={-1} className="rounded-2xl border border-success/30 bg-success/10 p-6 mb-5 outline-none focus-visible:ring-2 focus-visible:ring-success/40">
          <p className="text-[15px] font-semibold text-success">Access granted after step-up ✓</p>
          <p className="text-[13px] text-muted mt-1">{released.resource?.note}</p>
          <pre className="rounded-lg border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink mt-3">
            {JSON.stringify(released.resource, null, 2)}
          </pre>
          <button onClick={reset} className="text-[13px] text-muted hover:text-ink mt-3 underline-offset-2 hover:underline">
            Run again
          </button>
        </section>
      )}

      {err && <p className="text-[13px] text-danger mb-4">{err}</p>}

      {io && (
        <details className="mt-1">
          <summary className="text-[13px] text-muted cursor-pointer">Show the raw request / response</summary>
          <p className="text-[12px] text-faint mt-2">
            Two login sessions (connect, then step-up) and the credential the wallet presented in the step-up
            assertion (<span className="font-mono">verified</span>) — all public; your birthday is never disclosed.
          </p>
          <pre className="rounded-lg border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink mt-2">
            {JSON.stringify(io, null, 2)}
          </pre>
        </details>
      )}
    </main>
  );
}
