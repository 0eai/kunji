import React, { useEffect, useRef, useState } from 'react';

// The drop-in "Sign in with kunji" widget (rp.js) playground. rp.js is loaded globally in index.html
// (it defines window.kunji); here we render the real `<div data-kunji-signin>` and let the user pick which
// scopes to request — the wallet shows a consent toggle for each and returns only what's approved.
const SCOPES = [
  { id: 'profile', desc: 'share your self-asserted name / avatar (optional)', on: true },
  { id: 'offline_access', desc: 'a longer-lived, re-presentable grant', on: false },
  { id: 'vc:age_over_18', desc: 'request a verified credential predicate', on: false },
  { id: 'read:orders', desc: 'an app-defined, namespaced scope', on: false },
];

// claims are self-asserted + unverified → render the name as text, and only accept a picture with a safe
// scheme before binding it to <img src>.
const safePic = (p) => (typeof p === 'string' && /^(https:|data:image\/)/i.test(p) ? p : null);

export default function RpjsDemo({ onBack }) {
  const [checked, setChecked] = useState(() => Object.fromEntries(SCOPES.map((s) => [s.id, s.on])));
  const [result, setResult] = useState(null); // the kunji:success detail
  const mountRef = useRef(null);

  const scopes = SCOPES.filter((s) => checked[s.id]).map((s) => s.id);
  const scopeStr = scopes.join(' ');

  // (Re)mount the real drop-in widget whenever the scope selection changes — rp.js reads the data-attrs
  // once at mount, so we replace the node and re-render.
  useEffect(() => {
    const mount = mountRef.current;
    if (!mount || !window.kunji) return;
    mount.replaceChildren();
    const div = document.createElement('div');
    div.setAttribute('data-kunji-signin', '');
    div.setAttribute('data-app-name', 'kunji demo');
    div.setAttribute('data-audience', 'kunji-demo.web.app');
    div.setAttribute('data-session-url', 'https://kunji-demo.web.app/api/session');
    div.setAttribute('data-callback-url', 'https://kunji-demo.web.app/kunji/callback');
    div.setAttribute('data-poll-url', 'https://kunji-demo.web.app/kunji/status');
    if (scopes.length) div.setAttribute('data-scope', scopeStr);
    mount.appendChild(div);
    window.kunji.render(div);
  }, [scopeStr]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onSuccess = (e) => setResult(e.detail);
    document.addEventListener('kunji:success', onSuccess);
    return () => document.removeEventListener('kunji:success', onSuccess);
  }, []);

  const handle = result && window.kunji ? window.kunji.handle(result.sub) : null;
  const claims = result?.claims;
  const pic = claims ? safePic(claims.picture) : null;
  const shared = claims && (claims.name || claims.picture);

  return (
    <main className="flex-1 flex flex-col max-w-[34rem] w-full mx-auto px-6 py-10 animate-rise">
      <header className="flex items-center gap-2 mb-8">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · drop-in widget</span>
        {onBack && (
          <button onClick={onBack} className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline">
            ← demos
          </button>
        )}
      </header>

      <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Try the button</h1>
      <p className="text-[15px] text-muted mt-1 mb-6">
        The real <span className="font-mono text-ink">rp.js</span> widget (from{' '}
        <span className="font-mono text-ink">kunji.cc/rp.js</span>), wired to this demo's own endpoints. Pick the
        scopes to request — the wallet shows a consent toggle for each and returns only what you approve.
      </p>

      <section className="rounded-2xl border border-line p-6 mb-6">
        <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-3">Scopes to request</p>
        <div className="grid gap-[10px]">
          {SCOPES.map((s) => (
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
        <p className="text-[12px] text-muted mt-3">
          <span className="font-mono text-ink">login</span> is always implied.{' '}
          <span className="font-mono text-ink">data-scope</span> ={' '}
          <span className="font-mono text-ink">{scopeStr || '(none — login only)'}</span>
        </p>
      </section>

      <section className="rounded-2xl border border-line p-6 mb-6">
        <div ref={mountRef} />
      </section>

      {result && (
        <section className="rounded-2xl border border-line p-6 mb-6">
          <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-3">Signed in as</p>
          <div className="flex items-center gap-[14px]">
            <img
              src={pic || handle?.avatarDataUri}
              alt=""
              width="48"
              height="48"
              className="rounded-xl border border-line object-cover"
            />
            <span>
              <b className="text-[15px]">{(claims && claims.name) || handle?.name}</b>
              <small className="block text-muted text-[12px]">
                {shared ? 'shared from their kunji profile' : 'default identity (derived from sub)'}
              </small>
            </span>
          </div>
          <p className="text-[11px] uppercase tracking-[0.16em] text-faint mt-5 mb-2">kunji:success event</p>
          <pre className="rounded-xl border border-line bg-surface p-3 overflow-auto text-[12px] font-mono text-ink">
            {JSON.stringify(result, null, 2)}
          </pre>
        </section>
      )}
    </main>
  );
}
