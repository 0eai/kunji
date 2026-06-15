import React, { useRef, useState, useCallback, useEffect } from 'react';

// Agent-authorization live demo. kunji-agent-demo.js is loaded globally in index.html (it defines
// window.kunjiAgentDemo = { run, renderQr }); this drives a real authorization against the deployed demo RP
// (kunji-demo.web.app) + the kunji relay (app.kunji.cc), or replays a recorded sample. Full docs live on
// kunji.cc/developers/agents.
const AGENT_SCOPES = [
  { id: 'profile', desc: 'share name / avatar', on: false },
  { id: 'offline_access', desc: 'a longer-lived capability', on: true },
  { id: 'vc:age_over_18', desc: 'present a verified credential', on: false },
  { id: 'read:orders', desc: 'an app-defined action scope', on: false },
];

const short = (s, n = 12) => (s ? String(s).slice(0, n) + '…' : '');
const fmtCode = (c) => (c && c.length === 6 ? c.slice(0, 3) + ' ' + c.slice(3) : c || '— — —');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default function AgenticDemo({ onBack }) {
  const [tab, setTab] = useState('terminal');
  const [checked, setChecked] = useState(() => Object.fromEntries(AGENT_SCOPES.map((s) => [s.id, s.on])));
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(''); // 'sample' | 'live' | '' — which button is in flight
  const [io, setIo] = useState(null);

  const termRef = useRef(null);
  const codeRef = useRef(null);
  const statusRef = useRef(null);
  const qrRef = useRef(null);
  const abortRef = useRef(null);
  // Stop an in-flight live run (the relay poll loop) if the user navigates away mid-flow.
  useEffect(() => () => abortRef.current?.abort(), []);

  const termLine = useCallback((cls, text) => {
    const term = termRef.current;
    if (!term) return;
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text + '\n';
    term.appendChild(span);
    term.scrollTop = term.scrollHeight;
  }, []);

  const selectedScope = () => ['login', ...AGENT_SCOPES.filter((s) => checked[s.id]).map((s) => s.id)];

  // Map a step event to terminal lines + card updates. Same stream drives both skins (both in the DOM).
  const handleStep = useCallback(
    (ev) => {
      const d = ev.data || {};
      switch (ev.step) {
        case 'keygen':
          termLine('tdim', '$ agent keygen');
          termLine('', '  → agent key ' + short(d.agentPub, 16));
          break;
        case 'request':
          termLine('tdim', '$ agent authorize --audience ' + d.request.audience + ' --scope ' + d.request.scope.join(','));
          if (window.kunjiAgentDemo && qrRef.current) window.kunjiAgentDemo.renderQr(qrRef.current, d.request);
          break;
        case 'code':
          termLine('tac', '  → code ' + fmtCode(d.code) + '   — type this in your wallet');
          termLine('tdim', '    (or scan the QR in the “Card” tab)');
          if (codeRef.current) codeRef.current.textContent = fmtCode(d.code);
          if (statusRef.current) statusRef.current.textContent = 'Waiting for you to approve…';
          break;
        case 'await':
          termLine('tdim', '  ⠿ ' + (ev.label || 'awaiting approval in the wallet…'));
          break;
        case 'capability':
          termLine('tok', '  ✓ capability received & decrypted');
          termLine(
            'tdim',
            '    jti ' + short(d.capabilityClaims.jti, 12) + ' · scope ' + d.capabilityClaims.scope.join(',') +
              ' · exp ' + new Date(d.capabilityClaims.exp * 1000).toISOString().replace('T', ' ').slice(0, 19) + 'Z',
          );
          if (statusRef.current) statusRef.current.textContent = 'Capability received — logging in…';
          break;
        case 'session':
          termLine('', '  → session ' + short(d.sessionId, 10) + ' · challenge ' + short(d.challenge, 10));
          break;
        case 'proof':
          termLine('tok', '  ✓ signed holder-of-key proof');
          break;
        case 'login':
          termLine('', '  → POST /kunji/agent → ' + JSON.stringify(d.agentResponse));
          break;
        case 'status':
          termLine('tok', '  ✓ logged in as ' + short(d.status.sub, 16) + '  scope=' + (d.status.scope || []).join(',') + ' agent=' + d.status.agent);
          if (codeRef.current) codeRef.current.textContent = '✓';
          if (statusRef.current) statusRef.current.textContent = 'Signed in as ' + short(d.status.sub, 16) + ' · scope ' + (d.status.scope || []).join(',');
          break;
      }
    },
    [termLine],
  );

  const reset = useCallback(() => {
    if (termRef.current) termRef.current.replaceChildren();
    if (codeRef.current) codeRef.current.textContent = '— — —';
    if (qrRef.current) qrRef.current.replaceChildren();
    if (statusRef.current) statusRef.current.textContent = 'Idle.';
    setIo(null);
  }, []);

  const playSample = useCallback(async () => {
    if (busy) return;
    reset();
    setBusy(true);
    setRunning('sample');
    termLine('tdim', '# recorded sample — real signed artifacts, no wallet needed');
    try {
      const data = await fetch('/agent-demo-replay.json').then((r) => r.json());
      for (const ev of data.steps) {
        handleStep(ev);
        await sleep(ev.step === 'await' ? 1700 : 600);
      }
      if (data.result?.io) setIo(JSON.stringify(data.result.io, null, 2));
    } catch {
      termLine('tac', '  ✗ could not load the sample');
    } finally {
      setBusy(false);
      setRunning('');
    }
  }, [busy, reset, termLine, handleStep]);

  const runLive = useCallback(async () => {
    if (busy) return;
    if (!window.kunjiAgentDemo) {
      termLine('tac', '  ✗ demo module failed to load');
      return;
    }
    reset();
    setBusy(true);
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    setRunning('live');
    termLine('tdim', '# live — approve in your kunji wallet (Security → Authorize an agent)');
    try {
      const result = await window.kunjiAgentDemo.run({
        relayUrl: 'https://app.kunji.cc',
        rpBase: 'https://kunji-demo.web.app',
        audience: 'kunji-demo.web.app',
        scope: selectedScope(),
        onStep: handleStep,
        signal: abortRef.current.signal,
      });
      if (result?.io) setIo(JSON.stringify(result.io, null, 2));
    } catch (e) {
      termLine('tac', '  ✗ ' + (e.message || String(e)));
      if (statusRef.current) statusRef.current.textContent = 'Stopped: ' + (e.message || e);
    } finally {
      setBusy(false);
      setRunning('');
    }
  }, [busy, reset, termLine, handleStep, checked]); // eslint-disable-line react-hooks/exhaustive-deps

  const tabBtn = (id, label) => (
    <button
      onClick={() => setTab(id)}
      className={`pb-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        tab === id ? 'border-accent text-ink' : 'border-transparent text-faint hover:text-muted'
      }`}
    >
      {label}
    </button>
  );

  return (
    <main className="flex-1 flex flex-col max-w-[34rem] w-full mx-auto px-6 py-10 animate-rise">
      <header className="flex items-center gap-2 mb-8">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · agent authorization</span>
        {onBack && (
          <button onClick={onBack} className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline">
            ← demos
          </button>
        )}
      </header>

      <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Authorize an agent</h1>
      <p className="text-[15px] text-muted mt-1 mb-6">
        Watch an AI agent get authorized to act for you — a scoped, expiring, holder-of-key capability, never your
        keys. Runs the real flow against the demo RP + the kunji relay.{' '}
        <a href="https://kunji.cc/developers/agents" className="text-accent hover:text-ink underline underline-offset-2">
          Full docs →
        </a>
      </p>

      <div className="flex gap-6 border-b border-line mb-4">
        {tabBtn('terminal', 'Terminal')}
        {tabBtn('card', 'Card')}
      </div>

      <div hidden={tab !== 'terminal'}>
        <div className="term">
          <div className="term-bar">
            <span className="tdot r" /><span className="tdot y" /><span className="tdot g" />
            <span className="term-title">agent — kunji authorize</span>
          </div>
          <pre className="term-body" ref={termRef} aria-live="polite">
            <span className="tdim">$ press “Play sample” or “Run it live”…</span>
          </pre>
        </div>
      </div>

      <div hidden={tab !== 'card'}>
        <div className="rounded-2xl border border-line p-6 text-center bg-surface">
          <p className="text-[12px] text-muted mb-3">In your wallet → Security → Authorize an agent → type the code</p>
          <div ref={codeRef} className="font-mono tabular text-[34px] font-bold tracking-[0.3em] text-ink">— — —</div>
          <div className="flex justify-center my-4 min-h-[200px] items-center">
            <div ref={qrRef} className="leading-[0]" />
          </div>
          <p ref={statusRef} className="text-[13px] text-muted" aria-live="polite">Idle.</p>
        </div>
      </div>

      <div className="mt-6">
        <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-2">Scope to request (live run)</p>
        <div className="grid gap-2">
          {AGENT_SCOPES.map((s) => (
            <label key={s.id} className="flex gap-[10px] items-start cursor-pointer text-[14px]">
              <input
                type="checkbox"
                className="mt-[3px]"
                checked={!!checked[s.id]}
                onChange={(e) => setChecked((c) => ({ ...c, [s.id]: e.target.checked }))}
              />
              <span>
                <span className="font-mono text-ink">{s.id}</span>{' '}
                <span className="text-muted">— {s.desc}</span>
              </span>
            </label>
          ))}
        </div>
        <p className="text-[12px] text-muted mt-2">
          The wallet shows a toggle per item; <span className="font-mono text-ink">login</span> is always included.
        </p>
      </div>

      <div className="flex flex-wrap gap-3 mt-5">
        <button
          onClick={playSample}
          disabled={busy}
          className="inline-flex items-center justify-center px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity disabled:opacity-50"
        >
          {running === 'sample' ? 'Running…' : '▶ Play sample'}
        </button>
        <button
          onClick={runLive}
          disabled={busy}
          className="inline-flex items-center justify-center px-5 py-3 text-sm border border-line text-ink hover:border-accent hover:text-accent font-semibold rounded-full transition-colors disabled:opacity-50"
        >
          {running === 'live' ? 'Running…' : 'Run it live (needs your wallet)'}
        </button>
      </div>
      <p className="text-[12px] text-faint mt-3">
        “Play sample” replays a recorded run (real signed artifacts, no wallet). “Run it live” performs a new
        authorization you approve in the kunji app.
      </p>

      {io && (
        <details className="mt-4">
          <summary className="text-[13px] text-muted cursor-pointer">Show the raw request / response</summary>
          <pre className="rounded-xl border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink mt-2">
            {io}
          </pre>
        </details>
      )}
    </main>
  );
}
