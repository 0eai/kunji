import React from 'react';
// Shared kunji helper: derive the default pseudonymous identity (name + identicon)
// from `sub`. A third-party RP would use window.kunji.handle() from rp.js, or copy
// this small module. The algorithm is specified in docs/discoverable-login.md.
import { deriveHandle } from '../../../src/lib/kunjiHandle.js';

export default function Dashboard({ sub, claims, onLogout }) {
  // Prefer the user's consented custom profile; otherwise fall back to the default
  // identity derived from `sub`. `claims` are self-asserted + unverified — React
  // escapes the name on render, and the avatar is shown as an <img> (no server fetch).
  const fallback = deriveHandle(sub);
  const name = claims?.name || fallback.name;
  const avatar = claims?.picture || fallback.avatarDataUri;
  const isCustom = !!(claims && (claims.name || claims.picture));

  return (
    <>
      <header className="flex items-center gap-2 max-w-[26rem] w-full mx-auto px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · sign in</span>
        <a href="#" className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline">
          ← demos
        </a>
      </header>

      <main className="flex-1 flex flex-col justify-center max-w-[26rem] w-full mx-auto px-6 animate-rise">
        <div className="mb-9">
          <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Signed in</h1>
          <p className="text-[15px] text-muted mt-1">Verified with kunji — no password.</p>
        </div>

        {/* Resolved identity — how this app shows the user */}
        <div className="flex items-center gap-3.5 mb-7">
          <img
            src={avatar}
            alt=""
            className="w-12 h-12 rounded-xl border border-line object-cover shrink-0"
          />
          <div className="min-w-0">
            <p className="text-[15px] font-medium text-ink truncate">{name}</p>
            <p className="text-[12px] text-faint">
              {isCustom ? 'Shared from their kunji profile' : 'Default identity (from your ID)'}
            </p>
          </div>
        </div>

        <div className="mb-7">
          <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-2.5">
            Your ID for this app
          </p>
          <code className="block text-[12px] font-mono tabular text-ink break-all leading-relaxed border-y border-line py-3.5">
            {sub}
          </code>
          <p className="text-[12px] text-faint mt-2 leading-relaxed">
            The SHA-256 of your per-app public key — unique to this app, so other apps see a
            different ID. The name and icon above are derived from it unless you shared a profile.
          </p>
        </div>

        <button
          onClick={onLogout}
          className="inline-flex items-center justify-center w-fit text-sm font-medium text-muted hover:text-ink transition-colors"
        >
          Sign out
        </button>
      </main>
    </>
  );
}
