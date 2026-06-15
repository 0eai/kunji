import React, { useState, useRef, useEffect, useCallback } from 'react';
import { renderBrandedQr } from './qr.js';

// Verified-credentials demo: issuance (OpenID4VCI) + presentation (OpenID4VP) against the real kunji
// wallet. The page only renders the wallet-accepted QR/deep-link payloads + polls the verify result —
// the issuer + verifier are this demo's own Cloud Functions (see functions/index.js).
const KUNJI_APP_URL = 'https://app.kunji.cc';

export default function CredentialsDemo({ onBack }) {
  // 1. Issuance
  const [offerUri, setOfferUri] = useState('');
  const [offerErr, setOfferErr] = useState('');
  const offerQrRef = useRef(null);
  // 2. Presentation
  const [vpUri, setVpUri] = useState('');
  const [vpErr, setVpErr] = useState('');
  const [result, setResult] = useState(null); // null | 'waiting' | { claims }
  const vpQrRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (offerUri) renderBrandedQr(offerQrRef.current, offerUri);
  }, [offerUri]);
  useEffect(() => {
    if (vpUri) renderBrandedQr(vpQrRef.current, vpUri);
  }, [vpUri]);
  useEffect(() => () => clearInterval(pollRef.current), []);

  const getOffer = useCallback(async () => {
    setOfferErr('');
    try {
      const r = await fetch('/credential-offer');
      if (!r.ok) throw new Error('offer');
      setOfferUri((await r.json()).offerUri);
    } catch {
      setOfferErr('Could not reach the issuer. Try again.');
    }
  }, []);

  const proveAge = useCallback(async () => {
    setVpErr('');
    setResult(null);
    clearInterval(pollRef.current);
    try {
      const r = await fetch('/oid4vp/request');
      if (!r.ok) throw new Error('request');
      const { state, requestUri } = await r.json();
      setVpUri(requestUri);
      setResult('waiting');
      const check = async () => {
        if (document.hidden) return;
        try {
          const rr = await fetch(`/oid4vp/result?state=${encodeURIComponent(state)}`);
          if (!rr.ok) return;
          const s = await rr.json();
          if (s.approved) {
            clearInterval(pollRef.current);
            setResult({ claims: s.claims || {} });
          }
        } catch {
          /* transient */
        }
      };
      check();
      pollRef.current = setInterval(check, 2000);
    } catch {
      setVpErr('Could not reach the verifier. Try again.');
    }
  }, []);

  // Same-device deep links the wallet handles: ?vp= (present) and ?offer= (receive an OpenID4VCI offer).
  const vpDeepLink = vpUri ? `${KUNJI_APP_URL}/?vp=${encodeURIComponent(vpUri)}` : '';
  const offerDeepLink = offerUri ? `${KUNJI_APP_URL}/?offer=${encodeURIComponent(offerUri)}` : '';
  const [copied, setCopied] = useState(false);
  const copyOffer = async () => {
    try {
      await navigator.clipboard.writeText(offerUri);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  };

  return (
    <main className="flex-1 flex flex-col max-w-[34rem] w-full mx-auto px-6 py-10 animate-rise">
      <header className="flex items-center gap-2 mb-8">
        <img src="https://kunji.cc/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-medium text-faint">Kunji Demo · Verified credentials</span>
        {onBack && (
          <button onClick={onBack} className="ml-auto text-[13px] text-muted hover:text-ink underline-offset-2 hover:underline">
            ← Sign-in demo
          </button>
        )}
      </header>

      <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight">Verified credentials</h1>
      <p className="text-[15px] text-muted mt-1 mb-8">
        Get a demo credential into your kunji wallet, then prove a fact from it — selective disclosure, no
        account, the issuer never sees where you present it.
      </p>

      {/* Card 1 — issuance */}
      <section className="rounded-2xl border border-line p-6 mb-6">
        <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-1">Step 1 · OpenID4VCI</p>
        <h2 className="text-[1.25rem] font-semibold tracking-tight">Get a demo age credential</h2>
        <p className="text-[14px] text-muted mt-1">
          A signed SD-JWT VC with pre-baked age thresholds (booleans only — never your date of birth).
        </p>
        {!offerUri ? (
          <button
            onClick={getOffer}
            className="inline-flex items-center justify-center mt-5 px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity"
          >
            Get credential
          </button>
        ) : (
          <div className="mt-5">
            <div ref={offerQrRef} className="relative inline-flex rounded-2xl border border-line bg-white p-3" />
            <p className="text-[13px] text-muted mt-3">
              Scan with the kunji app, or tap below on this device, then approve.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              <a
                href={offerDeepLink}
                className="inline-flex items-center justify-center px-4 py-2 text-[13px] bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
              >
                Open in kunji on this device
              </a>
              <button
                onClick={copyOffer}
                className="inline-flex items-center justify-center px-4 py-2 text-[13px] border border-line text-muted hover:text-ink rounded-full transition-colors"
              >
                {copied ? 'Copied ✓' : 'Copy offer'}
              </button>
            </div>
            <p className="text-[12px] text-faint mt-3">
              This offer is single-use and expires shortly.{' '}
              <button onClick={getOffer} className="text-accent hover:text-ink underline underline-offset-2">
                Get a fresh offer
              </button>{' '}
              if it was already used.
            </p>
          </div>
        )}
        {offerErr && <p className="text-[13px] text-danger mt-3">{offerErr}</p>}
      </section>

      {/* Card 2 — presentation */}
      <section className="rounded-2xl border border-line p-6">
        <p className="text-[11px] uppercase tracking-[0.16em] text-faint mb-1">Step 2 · OpenID4VP</p>
        <h2 className="text-[1.25rem] font-semibold tracking-tight">Prove you&rsquo;re over 18</h2>
        <p className="text-[14px] text-muted mt-1">
          The demo asks only for <span className="font-mono text-ink">age_over_18</span>. Nothing else from the
          credential is revealed.
        </p>
        {result && result.claims ? (
          <div className="mt-5 rounded-xl bg-success/10 border border-success/30 p-4">
            <p className="text-[15px] font-semibold text-success">Verified — over 18 ✓</p>
            <p className="text-[13px] text-muted mt-1">
              Disclosed: <span className="font-mono text-ink">{JSON.stringify(result.claims)}</span>
            </p>
            <button onClick={proveAge} className="text-[13px] text-muted hover:text-ink mt-3 underline-offset-2 hover:underline">
              Run again
            </button>
          </div>
        ) : !vpUri ? (
          <button
            onClick={proveAge}
            className="inline-flex items-center justify-center mt-5 px-5 py-3 text-sm bg-ink hover:opacity-90 text-paper font-semibold rounded-full transition-opacity"
          >
            Prove you&rsquo;re over 18
          </button>
        ) : (
          <div className="mt-5">
            <div ref={vpQrRef} className="relative inline-flex rounded-2xl border border-line bg-white p-3" />
            <p className="text-[13px] text-muted mt-3">Scan with the kunji app, or tap below on this device, then approve.</p>
            <a
              href={vpDeepLink}
              className="inline-flex items-center justify-center mt-3 px-4 py-2 text-[13px] bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full transition-colors"
            >
              Open in kunji on this device
            </a>
            <p className="text-[13px] text-accent mt-3">Waiting for you to present in kunji…</p>
          </div>
        )}
        {vpErr && <p className="text-[13px] text-danger mt-3">{vpErr}</p>}
      </section>

      <p className="text-[12px] text-faint mt-8 leading-relaxed">
        Demo issuer — it mints to anyone for the demo. A real issuer authenticates you first. The credential is
        only trusted by this demo verifier.
      </p>
    </main>
  );
}
