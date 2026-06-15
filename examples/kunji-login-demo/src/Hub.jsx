import React from 'react';

// The demo hub — the home of every live kunji demo (demo.kunji.cc). Each card links to one of the
// five SPA hash routes: #login, #rpjs, #credentials, #agentic, #stepup.
const KeyMark = () => (
  <svg viewBox="0 0 512 512" width="18" height="18" aria-hidden="true">
    <g
      transform="rotate(-40 256 256)"
      fill="none"
      stroke="currentColor"
      strokeWidth="58"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="240" cy="172" r="56" fill="currentColor" />
      <path d="M240 172 V398" />
      <path d="M240 334 L300 314" />
      <path d="M240 334 L300 358" />
    </g>
  </svg>
);

const DEMOS = [
  {
    href: '#login',
    title: 'Sign in with kunji',
    blurb: 'Passwordless, anonymous sign-in. Scan a QR or type a code; pick which scopes to request.',
    tag: 'Sign-in',
  },
  {
    href: '#rpjs',
    title: 'Drop-in widget',
    blurb: 'The one-line “Sign in with kunji” button (rp.js) on a blank page — toggle scopes and watch the result.',
    tag: 'rp.js',
  },
  {
    href: '#credentials',
    title: 'Verified credentials',
    blurb: 'Issue an age credential (SD-JWT or unlinkable BBS) into your wallet, then prove a threshold — selective disclosure.',
    tag: 'OpenID4VC',
  },
  {
    href: '#agentic',
    title: 'Agent authorization',
    blurb: 'Authorize an AI agent to act for you via a scoped, expiring, holder-of-key capability — never your keys.',
    tag: 'Agentic',
  },
  {
    href: '#stepup',
    title: 'Step-up authorization',
    blurb: 'Connect once with a narrow scope, then approve only the delta when an app asks for more later.',
    tag: 'Step-up',
  },
];

export default function Hub() {
  return (
    <main className="flex-1 flex flex-col max-w-[44rem] w-full mx-auto px-6 py-12 animate-rise">
      <header className="flex items-center gap-2 mb-10">
        <img src="/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">kunji · demos</span>
        <a
          href="https://kunji.cc"
          className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline"
        >
          kunji.cc ↗
        </a>
      </header>

      <h1 className="text-[2.25rem] leading-[1.1] font-semibold tracking-tight">Live demos</h1>
      <p className="text-[15px] text-muted mt-2 mb-10 max-w-[34rem]">
        Try kunji end-to-end against the real wallet — no backend in the login path, the servers store only
        ciphertext. Each demo is a configurable playground.
      </p>

      <div className="grid sm:grid-cols-2 gap-4">
        {DEMOS.map((d) => (
          <a
            key={d.href}
            href={d.href}
            className="group rounded-2xl border border-line p-6 bg-surface hover:border-faint transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-[0.16em] text-faint">{d.tag}</span>
              <span className="text-accent opacity-60 group-hover:opacity-100 transition-opacity">
                <KeyMark />
              </span>
            </div>
            <h2 className="text-[1.25rem] font-semibold tracking-tight mt-3 group-hover:text-accent transition-colors">
              {d.title}
            </h2>
            <p className="text-[14px] text-muted mt-1 leading-relaxed">{d.blurb}</p>
            <span className="inline-block text-[13px] text-accent mt-4 underline-offset-2 group-hover:underline">
              Open demo →
            </span>
          </a>
        ))}
      </div>

      <p className="text-[12px] text-faint mt-12 leading-relaxed">
        Demo issuer/verifier mint to anyone — a real issuer authenticates you first. Credentials here are
        trusted only by this demo. Source:{' '}
        <a
          href="https://github.com/0eai/kunji"
          target="_blank"
          rel="noopener"
          className="text-muted hover:text-ink underline underline-offset-2"
        >
          github.com/0eai/kunji
        </a>
        .
      </p>
    </main>
  );
}
