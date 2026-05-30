import React from 'react';

export default function Dashboard({ sub, onLogout }) {
  return (
    <>
      <header className="flex items-center gap-2 max-w-[26rem] w-full mx-auto px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <span className="text-[15px] font-medium text-faint">Kunji Demo</span>
      </header>

      <main className="flex-1 flex flex-col justify-center max-w-[26rem] w-full mx-auto px-6 animate-rise">
        <div className="mb-9">
          <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Signed in</h1>
          <p className="text-[15px] text-muted mt-1">Verified with kunji — no password.</p>
        </div>

        <div className="mb-7">
          <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-2.5">Your ID for this app</p>
          <code className="block text-[12px] font-mono tabular text-ink break-all leading-relaxed border-y border-line py-3.5">
            {sub}
          </code>
          <p className="text-[12px] text-faint mt-2 leading-relaxed">
            The SHA-256 of your per-app public key — unique to this app, so other apps see a different ID.
          </p>
        </div>

        <button onClick={onLogout}
          className="inline-flex items-center justify-center w-fit text-sm font-medium text-muted hover:text-ink transition-colors">
          Sign out
        </button>
      </main>
    </>
  );
}
