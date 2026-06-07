import React, { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { ShieldCheck, ScanLine, Copy, CheckCircle2 } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Field } from './ui/primitives';
import {
  parseAgentRequest,
  issueCapability,
  depositAgentCapability,
  recordAgent,
} from '../services/capability';
import { renderBrandedQr } from '../lib/brandedQr';
import { useToast } from '../contexts/ToastContext';

const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));

const TTLS = [
  { label: '1 hour', s: 3600 },
  { label: '24 hours', s: 86400 },
  { label: '7 days', s: 604800 },
];

// Wallet flow to authorize an agent: scan/paste the agent's request, review the requested
// scope + audience, pick a TTL, then explicitly approve to mint a capability the agent
// holds. The agent never receives any kunji key — only this scoped, expiring capability.
const AuthorizeAgentSheet = ({ userId, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [phase, setPhase] = useState('scan'); // scan → review → issued
  const [showScanner, setShowScanner] = useState(false);
  const [paste, setPaste] = useState('');
  const [req, setReq] = useState(null); // { audience, scope, agentPub }
  const [ttl, setTtl] = useState(3600);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null); // mint result
  const [copied, setCopied] = useState(false);
  const [delivered, setDelivered] = useState(false); // v2: relayed to the agent automatically
  const qrRef = useRef(null);

  // Styled QR of the capability (no logo — it's a long opaque token; lighter EC).
  useEffect(() => {
    if (phase === 'issued' && result && qrRef.current) {
      // Long JWT → keep modules legible: bigger, EC 'L' (fewer modules), no internal margin
      // (the container's white padding is the single quiet zone — avoids a double frame).
      renderBrandedQr(qrRef.current, {
        data: result.capability,
        size: 240,
        withLogo: false,
        ec: 'L',
        margin: 0,
      });
    }
  }, [phase, result]);

  const ingest = (raw) => {
    setShowScanner(false);
    setError('');
    try {
      setReq(parseAgentRequest(raw));
      setPhase('review');
    } catch {
      setError('Not a valid kunji agent request.');
    }
  };

  const approve = async () => {
    setBusy(true);
    try {
      const r = await issueCapability(userId, masterKey, {
        audience: req.audience,
        scope: req.scope,
        ttlSeconds: ttl,
        agentPub: req.agentPub,
      });
      setResult(r);
      setPhase('issued');
      // Record the capability metadata so it shows in "Authorized agents" (and can be revoked).
      // Best-effort — never block the issuance flow on it.
      recordAgent(masterKey, {
        jti: r.jti,
        audience: req.audience,
        scope: req.scope,
        exp: r.exp,
        agentPub: req.agentPub,
      }).catch((e) => console.warn('recordAgent failed:', e));
      // v2: deliver the capability to the agent over the encrypted relay (no manual copy).
      // Best-effort — on any failure the user still has the QR + copy fallback below.
      if (req.sessionId && req.transportPub) {
        try {
          await depositAgentCapability(req.sessionId, req.transportPub, r.capability, req.audience);
          setDelivered(true);
        } catch (e) {
          showToast('Authorized, but auto-delivery failed — copy or scan it below.', 'error');
          console.warn('Agent capability relay failed:', e);
        }
      }
    } catch (e) {
      showToast('Could not authorize: ' + (e.message || e), 'error');
    } finally {
      setBusy(false);
    }
  };

  const copy = () => {
    navigator.clipboard.writeText(result.capability);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="agent-title">
      {phase === 'review' && req ? (
        <>
          <div className="flex items-center gap-2.5 mb-1">
            <ShieldCheck size={18} className="text-success" />
            <h2 id="agent-title" className="text-lg font-semibold tracking-tight">
              Authorize an agent
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-4">
            An agent is requesting access to{' '}
            <span className="font-mono text-ink">{req.audience}</span>. It will act for you there
            within this scope until the capability expires — it never receives your keys.
          </p>
          <div className="flex flex-wrap gap-1.5 mb-5">
            {req.scope.map((s) => (
              <span key={s} className="text-[12px] font-mono px-2 py-1 rounded-md bg-accent-soft text-accent">
                {s}
              </span>
            ))}
          </div>
          <div className="text-[12px] uppercase tracking-wide text-faint mb-2">Expires after</div>
          <div className="flex gap-1 p-1 rounded-full border border-line w-fit mb-6">
            {TTLS.map((t) => (
              <button
                key={t.s}
                onClick={() => setTtl(t.s)}
                className={`px-4 py-1.5 rounded-full text-[13px] font-medium transition-colors ${
                  ttl === t.s ? 'bg-accent-soft text-accent' : 'text-muted hover:text-ink'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={onClose} disabled={busy}>
              Cancel
            </Btn>
            <Btn variant="primary" onClick={approve} disabled={busy}>
              {busy ? 'Authorizing…' : 'Approve'}
            </Btn>
          </div>
        </>
      ) : phase === 'issued' && result ? (
        <>
          <div className="flex items-center gap-2.5 mb-1">
            <ShieldCheck size={18} className="text-success" />
            <h2 id="agent-title" className="text-lg font-semibold tracking-tight">
              Agent authorized
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-4">
            {delivered ? (
              <>Sent to the agent securely. It's scoped to </>
            ) : (
              <>Give this capability to the agent (copy it, or let it scan the code). It's scoped to </>
            )}
            <span className="font-mono text-ink">{req.audience}</span> and expires automatically.
          </p>
          {delivered && (
            <div className="flex items-center gap-2 text-[13px] text-success mb-4">
              <CheckCircle2 size={15} className="shrink-0" />
              <span>Delivered to the agent — no copying needed. The QR/token below is a backup.</span>
            </div>
          )}
          <div className="flex justify-center mb-4">
            <div ref={qrRef} aria-label="Capability QR" className="rounded-xl border border-line p-3 bg-white" />
          </div>
          <div className="flex items-start gap-3 border-y border-line py-3 mb-4">
            <code className="flex-1 text-[11px] font-mono text-ink break-all leading-relaxed max-h-24 overflow-y-auto">
              {result.capability}
            </code>
            <button onClick={copy} className="shrink-0 text-muted hover:text-ink transition-colors" title="Copy">
              {copied ? <CheckCircle2 size={15} className="text-success" /> : <Copy size={15} />}
            </button>
          </div>
          <div className="flex justify-end">
            <Btn variant="primary" onClick={onClose}>
              Done
            </Btn>
          </div>
        </>
      ) : (
        <>
          <h2 id="agent-title" className="text-lg font-semibold tracking-tight mb-1">
            Authorize an agent
          </h2>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            Let an agent — an AI assistant, script, or service — act for you at one app, within a
            scope you approve, without giving it any of your keys. Scan or paste the agent's request
            to begin.
          </p>
          <Btn variant="primary" onClick={() => setShowScanner(true)} className="w-full mb-4">
            <ScanLine size={16} /> Scan agent request
          </Btn>
          <Field
            label="…or paste the request"
            value={paste}
            onChange={(e) => {
              setPaste(e.target.value);
              if (error) setError('');
            }}
          />
          {error && <p className="text-danger text-[13px] mt-2">{error}</p>}
          <div className="flex justify-end mt-4">
            <Btn variant="quiet" onClick={() => ingest(paste)} disabled={!paste.trim()}>
              Use pasted request
            </Btn>
          </div>
        </>
      )}

      {showScanner && (
        <Suspense fallback={<div className="fixed inset-0 z-[200] bg-black" />}>
          <QRScannerOverlay onScan={ingest} onClose={() => setShowScanner(false)} />
        </Suspense>
      )}
    </Sheet>
  );
};

export default AuthorizeAgentSheet;
