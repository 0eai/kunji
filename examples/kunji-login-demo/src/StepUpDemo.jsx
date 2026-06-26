import React, { useRef, useState, useCallback, useEffect } from 'react';

// Step-up authorization demo (push-relay.md Transport ①). Connect an agent with the narrow `login`
// scope, hit a scope-gated RP action (/api/profile → 403 insufficient_scope), then re-authorize the
// SAME agent for `read:profile` — the wallet shows a DELTA re-consent ("already connected") — and the
// retried action returns 200. Two real approvals in your wallet. Driven by window.kunjiAgentDemo.runStepUp
// (loaded in index.html). Notifications (Transport ②) are explained below — the full push demo is the
// kunji-agent-demo CLI.
const short = (s, n = 14) => (s ? String(s).slice(0, n) + '…' : '');

export default function StepUpDemo({ onBack }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null); // { scope, profile, steppedUp }
  const [pushBusy, setPushBusy] = useState(false);
  const [pushResult, setPushResult] = useState(null);
  const [showChannel, setShowChannel] = useState(false); // reveal the channel-id paste field mid-flow
  const [channelInput, setChannelInput] = useState('');
  const termRef = useRef(null);
  const codeRef = useRef(null);
  const qrRef = useRef(null);
  const linkRef = useRef(null);
  const statusRef = useRef(null);
  const abortRef = useRef(null);
  const resultRef = useRef(null);
  const channelResolveRef = useRef(null); // resolves runPushStepUp's getChannelId() promise
  // Stop the in-flight two-round flow (relay polling) if the user navigates away mid-run.
  useEffect(() => () => abortRef.current?.abort(), []);
  // Move focus to the granted panel when it appears (keyboard/SR users land on the result).
  useEffect(() => {
    if (result?.profile) resultRef.current?.focus();
  }, [result]);

  const termLine = useCallback((cls, text) => {
    const t = termRef.current;
    if (!t) return;
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text + '\n';
    t.appendChild(span);
    t.scrollTop = t.scrollHeight;
  }, []);

  const fmtCode = (c) => (c && c.length === 6 ? c.slice(0, 3) + ' ' + c.slice(3) : c || '— — —');

  const handleStep = useCallback(
    (ev) => {
      const d = ev.data || {};
      const rnd = d.round ? ` (round ${d.round})` : '';
      switch (ev.step) {
        case 'keygen':
          termLine('tdim', '$ agent keygen');
          termLine('', '  → agent key ' + short(d.agentPub, 16));
          break;
        case 'request':
          termLine('tdim', `$ agent authorize --scope ${d.request.scope.join(',')}${rnd}`);
          if (window.kunjiAgentDemo && qrRef.current) window.kunjiAgentDemo.renderQr(qrRef.current, d.request);
          if (linkRef.current && d.deepLink) linkRef.current.href = d.deepLink;
          break;
        case 'code':
          termLine('tac', '  → code ' + fmtCode(d.code) + '   — type it in your wallet, or tap below');
          if (codeRef.current) codeRef.current.textContent = fmtCode(d.code);
          if (linkRef.current && d.deepLink) linkRef.current.href = d.deepLink;
          if (statusRef.current) statusRef.current.textContent = `Waiting for approval${rnd}…`;
          break;
        case 'await':
          termLine('tdim', '  ⠿ ' + (ev.label || 'awaiting approval in the wallet…'));
          break;
        case 'capability':
          termLine('tok', '  ✓ capability received · scope ' + (d.capabilityClaims?.scope || []).join(','));
          break;
        case 'login':
          termLine('tok', '  ✓ logged in · scope ' + ((d.scope) || []).join(','));
          break;
        case 'gated-denied':
          termLine('tac', `  ✗ GET /api/profile → 403 insufficient_scope (needs "${d.need}")`);
          if (statusRef.current) statusRef.current.textContent = `Denied — the agent only has "login".`;
          break;
        case 'stepup':
          termLine('tdim', `  ↑ step-up: requesting "${d.need}" — approve the delta in your wallet`);
          break;
        case 'channel':
          termLine('tok', '  ✓ received the push channel automatically — no copy/paste');
          if (statusRef.current) statusRef.current.textContent = 'Got the channel automatically — pinging…';
          break;
        case 'need-channel':
          termLine('tdim', '  ⠿ enable “Notify me” in the wallet, then paste the channel id below');
          if (statusRef.current) statusRef.current.textContent = 'Turn on “Notify me” in the wallet, then paste its channel id.';
          break;
        case 'dispatched':
          termLine('tok', '  ✓ pushed to the wallet — approve the notification on your device');
          if (statusRef.current) statusRef.current.textContent = 'Pushed — approve the notification on your device.';
          break;
        case 'gated-ok':
          termLine('tok', `  ✓ GET /api/profile → ${d.status || 200} — released`);
          break;
      }
    },
    [termLine],
  );

  const run = useCallback(async () => {
    if (busy || !window.kunjiAgentDemo?.runStepUp) {
      if (!window.kunjiAgentDemo?.runStepUp) termLine('tac', '  ✗ demo module failed to load');
      return;
    }
    if (termRef.current) termRef.current.replaceChildren();
    if (codeRef.current) codeRef.current.textContent = '— — —';
    if (qrRef.current) qrRef.current.replaceChildren();
    if (statusRef.current) statusRef.current.textContent = 'Idle.';
    setResult(null);
    setBusy(true);
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    termLine('tdim', '# live — approve TWICE in your kunji wallet (connect, then step-up)');
    try {
      const r = await window.kunjiAgentDemo.runStepUp({
        relayUrl: 'https://app.kunji.cc',
        rpBase: 'https://kunji-demo.web.app',
        audience: 'kunji-demo.web.app',
        onStep: handleStep,
        signal: abortRef.current.signal,
      });
      setResult(r);
      if (statusRef.current) statusRef.current.textContent = r.steppedUp ? 'Stepped up — access granted.' : 'Done.';
    } catch (e) {
      termLine('tac', '  ✗ ' + (e.message || String(e)));
      if (statusRef.current) statusRef.current.textContent = 'Stopped: ' + (e.message || e);
    } finally {
      setBusy(false);
    }
  }, [busy, handleStep, termLine]);

  // Push step-up (Transport ②): connect, then ping the wallet via Web Push to approve the delta. The wallet
  // shows a NOTIFICATION; tapping it opens the re-consent sheet. Needs the channel id the wallet reveals when
  // you turn on "Notify me" — collected mid-flow via the getChannelId callback.
  const runPush = useCallback(async () => {
    if (busy || pushBusy || !window.kunjiAgentDemo?.runPushStepUp) {
      if (!window.kunjiAgentDemo?.runPushStepUp) termLine('tac', '  ✗ demo module failed to load');
      return;
    }
    if (termRef.current) termRef.current.replaceChildren();
    if (codeRef.current) codeRef.current.textContent = '— — —';
    if (qrRef.current) qrRef.current.replaceChildren();
    if (statusRef.current) statusRef.current.textContent = 'Idle.';
    setResult(null);
    setPushResult(null);
    setShowChannel(false);
    setChannelInput('');
    setPushBusy(true);
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    termLine('tdim', '# push demo — approve to connect + turn on “Notify me”, then ping via push');
    try {
      const r = await window.kunjiAgentDemo.runPushStepUp({
        relayUrl: 'https://app.kunji.cc',
        rpBase: 'https://kunji-demo.web.app',
        audience: 'kunji-demo.web.app',
        onStep: handleStep,
        signal: abortRef.current.signal,
        getChannelId: () =>
          new Promise((resolve) => {
            channelResolveRef.current = resolve;
            setShowChannel(true);
          }),
      });
      setPushResult(r);
      if (statusRef.current) statusRef.current.textContent = 'Stepped up via push — access granted.';
    } catch (e) {
      termLine('tac', '  ✗ ' + (e.message || String(e)));
      if (statusRef.current) statusRef.current.textContent = 'Stopped: ' + (e.message || e);
    } finally {
      setPushBusy(false);
      setShowChannel(false);
    }
  }, [busy, pushBusy, handleStep, termLine]);

  const submitChannel = useCallback(() => {
    const v = channelInput.trim();
    if (!/^[0-9a-f]{64}$/i.test(v)) {
      if (statusRef.current) statusRef.current.textContent = 'That doesn’t look like a channel id (64 hex).';
      return;
    }
    setShowChannel(false);
    channelResolveRef.current?.(v);
  }, [channelInput]);

  return (
    <main className="flex-1 flex flex-col max-w-[34rem] w-full mx-auto px-6 py-10 animate-rise">
      <header className="flex items-center gap-2 mb-8">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · step-up</span>
        {onBack && (
          <button onClick={onBack} className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline">
            ← demos
          </button>
        )}
      </header>

      <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Ask for more, later</h1>
      <p className="text-[15px] text-muted mt-1 mb-6">
        An agent connects with the narrow <span className="font-mono text-ink">login</span> scope, then hits an
        action that needs more. Instead of over-asking up front, it <b>steps up</b>: the wallet shows only the{' '}
        <b>delta</b> to approve, and the action goes through. No new kunji infrastructure.{' '}
        <a href="https://kunji.cc/developers/agents" className="text-accent hover:text-ink underline underline-offset-2">
          Docs →
        </a>
      </p>

      <div className="term mb-4">
        <div className="term-bar">
          <span className="tdot r" /><span className="tdot y" /><span className="tdot g" />
          <span className="term-title">agent — kunji step-up</span>
        </div>
        <pre className="term-body" ref={termRef} aria-live="polite">
          <span className="tdim">$ press “Run the step-up demo”…</span>
        </pre>
      </div>

      <div className="rounded-2xl border border-line p-6 text-center bg-surface mb-5">
        <p className="text-[12px] text-muted mb-3">Approve in your wallet — type the code, or tap to open kunji</p>
        <div ref={codeRef} className="font-mono tabular text-[34px] font-bold tracking-[0.3em] text-ink">— — —</div>
        <div className="flex justify-center my-4 min-h-[200px] items-center">
          <div ref={qrRef} className="leading-[0]" />
        </div>
        <a
          ref={linkRef}
          href="#"
          target="_blank"
          rel="noopener"
          className="inline-flex items-center justify-center px-4 py-2 text-[13px] bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
        >
          Open in kunji on this device
        </a>
        <p ref={statusRef} className="text-[13px] text-muted mt-3" aria-live="polite">Idle.</p>
      </div>

      <button
        onClick={run}
        disabled={busy || pushBusy}
        className="inline-flex items-center justify-center px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity disabled:opacity-50 self-start"
      >
        {busy ? 'Running…' : 'Run the step-up demo (deep link · Transport ①)'}
      </button>

      {result && result.profile && (
        <div ref={resultRef} tabIndex={-1} className="mt-5 rounded-xl bg-success/10 border border-success/30 p-4 outline-none focus-visible:ring-2 focus-visible:ring-success/40">
          <p className="text-[15px] font-semibold text-success">Access granted after step-up ✓</p>
          <p className="text-[13px] text-muted mt-1">
            Scope: <span className="font-mono text-ink">{(result.scope || []).join(', ')}</span>
          </p>
          <pre className="rounded-lg border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink mt-2">
            {JSON.stringify(result.profile, null, 2)}
          </pre>
        </div>
      )}

      {result?.io && (
        <details className="mt-4">
          <summary className="text-[13px] text-muted cursor-pointer">Show the raw request / response</summary>
          <p className="text-[12px] text-faint mt-2">
            The two capability claim-sets show the scope delta (<span className="font-mono">round1</span> →{' '}
            <span className="font-mono">round2</span>); <span className="font-mono">need</span> is the 403's missing
            scope. All public — no key material reaches this page.
          </p>
          <pre className="rounded-lg border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink mt-2">
            {JSON.stringify(result.io, null, 2)}
          </pre>
        </details>
      )}

      <section className="rounded-2xl border border-line p-6 mt-8">
        <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-2">Notifications — push step-up (Transport ②)</p>
        <p className="text-[14px] text-muted mb-4">
          Instead of a deep link, a channel-less agent can ping you via <b>Web Push</b> to approve a step-up
          while you're away — the push carries only an <b>opaque pointer</b>, never the request. Just connect
          and turn on <b>“Notify me”</b> in the wallet — it hands the agent its push channel automatically (over
          the encrypted relay), so there's no copy/paste. (If your wallet predates that, paste the channel id
          when asked.)
        </p>

        <button
          onClick={runPush}
          disabled={busy || pushBusy}
          className="inline-flex items-center justify-center px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity disabled:opacity-50"
        >
          {pushBusy ? 'Running…' : 'Run the push demo (needs your wallet + notifications)'}
        </button>

        {showChannel && (
          <div className="mt-4 rounded-xl border border-accent/40 bg-accent-soft/40 p-4">
            <label htmlFor="chan" className="block text-[12px] text-muted mb-2">
              Paste the <b>channel id</b> the wallet showed when you turned on “Notify me”:
            </label>
            <div className="flex gap-2">
              <input
                id="chan"
                value={channelInput}
                onChange={(e) => setChannelInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && submitChannel()}
                placeholder="64-hex channel id"
                className="flex-1 min-w-0 rounded-lg border border-line bg-surface px-3 py-2 text-[13px] font-mono text-ink outline-none focus:border-accent"
              />
              <button
                onClick={submitChannel}
                className="shrink-0 inline-flex items-center justify-center px-4 py-2 text-[13px] bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
              >
                Ping me via push
              </button>
            </div>
          </div>
        )}

        {pushResult && pushResult.profile && (
          <div className="mt-4 rounded-xl bg-success/10 border border-success/30 p-4">
            <p className="text-[15px] font-semibold text-success">Stepped up via push ✓</p>
            <p className="text-[13px] text-muted mt-1">
              Scope: <span className="font-mono text-ink">{(pushResult.scope || []).join(', ')}</span>
            </p>
            <pre className="rounded-lg border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink mt-2">
              {JSON.stringify(pushResult.profile, null, 2)}
            </pre>
          </div>
        )}

        <p className="text-[12px] text-faint mt-4">
          The push carries only the opaque pointer; the request itself rides the encrypted relay. Docs:{' '}
          <a href="https://kunji.cc/developers/agents" className="text-accent hover:text-ink underline underline-offset-2">
            agents →
          </a>
        </p>
      </section>
    </main>
  );
}
