import React, { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { ShieldCheck, ScanLine, Copy, CheckCircle2, Circle } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Field } from './ui/primitives';
import {
  parseAgentRequest,
  lookupAgentRequest,
  issueCapability,
  depositAgentCapability,
  recordAgent,
  revokeAgent,
  listAgents,
} from '../services/capability';
import { scopeId, scopeSatisfies } from '../lib/capability';
import { formatConstraints } from '../lib/scopeFormat';
import { pushSupported, enablePushForAudience, agentNotifyAllowed } from '../services/push';
import { renderBrandedQr } from '../lib/brandedQr';
import { useToast } from '../contexts/ToastContext';

const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));

const TTLS = [
  { label: '1 hour', s: 3600 },
  { label: '24 hours', s: 86400 },
  { label: '7 days', s: 604800 },
];

// Friendly text for the reserved-core scopes (docs/scope.md). Custom scopes have no vetted text —
// the wallet shows the raw id + the request's untrusted, RP-supplied label.
const RESERVED_LABELS = {
  login: 'Sign in as you',
  profile: 'Share your profile (name & avatar)',
  offline_access: 'Act without re-approval until it expires',
};

// Wallet flow to authorize an agent: scan/paste the agent's request, review the requested
// scope + audience, pick a TTL, then explicitly approve to mint a capability the agent
// holds. The agent never receives any kunji key — only this scoped, expiring capability.
const AuthorizeAgentSheet = ({ userId, masterKey, initialRequest, onClose }) => {
  const { showToast } = useToast();
  const [phase, setPhase] = useState('scan'); // scan → review → issued
  const [showScanner, setShowScanner] = useState(false);
  const [paste, setPaste] = useState('');
  const [code, setCode] = useState('');
  const [req, setReq] = useState(null); // { audience, scope, agentPub, scopeLabels? }
  const [grantedIds, setGrantedIds] = useState(() => new Set()); // per-item consent (default-deny)
  const [ttl, setTtl] = useState(3600);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null); // mint result
  const [copied, setCopied] = useState(false);
  const [delivered, setDelivered] = useState(false); // v2: relayed to the agent automatically
  const [prior, setPrior] = useState([]); // live caps this SAME agent already holds here (step-up)
  const [revokePrior, setRevokePrior] = useState(false); // replace the old capability on approve
  const [notify, setNotify] = useState(false); // opt-in Web Push channel (Transport ②), default off
  const [pushChannelId, setPushChannelId] = useState(''); // set after a channel is registered
  const qrRef = useRef(null);

  // The union of scope already granted to this agent for this audience — used to mark which requested
  // items are new vs. already-held, and to pre-tick the ones already covered (push-relay.md Transport ①).
  const priorScope = prior.flatMap((a) => a.scope || []);
  const alreadyGranted = (s) =>
    prior.length > 0 && scopeId(s) !== 'login' && scopeSatisfies(priorScope, [s]);

  // Styled QR of the capability (no logo — it's a long opaque token; lighter EC).
  useEffect(() => {
    if (phase === 'issued' && result && qrRef.current) {
      // Long JWT → keep modules legible: bigger, EC 'L' (fewer modules), no internal margin
      // (the container's white padding is the single quiet zone — avoids a double frame).
      renderBrandedQr(qrRef.current, {
        data: result.capability,
        size: 224,
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
      setGrantedIds(new Set()); // default-deny: nothing granted until the user toggles it on
      setPrior([]);
      setRevokePrior(false);
      setPhase('review');
    } catch {
      setError('Not a valid kunji agent request.');
    }
  };

  // Deep-link / programmatic entry (?authorize=…): ingest a provided request straight to review.
  useEffect(() => {
    if (initialRequest) ingest(initialRequest);
  }, [initialRequest]);

  // Step-up awareness: when a request is under review, look up any capability THIS SAME agent
  // already holds for this audience. If found, pre-tick the requested items already covered (still
  // editable) and default to replacing the old capability — the rest renders as the new delta.
  useEffect(() => {
    if (phase !== 'review' || !req) return;
    let cancelled = false;
    listAgents(masterKey)
      .then((agents) => {
        if (cancelled) return;
        const mine = agents.filter((a) => a.audience === req.audience && a.agentPub === req.agentPub);
        if (!mine.length) return;
        setPrior(mine);
        setRevokePrior(true); // default: the new capability supersedes the old one
        const held = mine.flatMap((a) => a.scope || []);
        setGrantedIds((prev) => {
          const next = new Set(prev);
          for (const s of req.scope) {
            const id = scopeId(s);
            if (id !== 'login' && scopeSatisfies(held, [s])) next.add(id);
          }
          return next;
        });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [phase, req, masterKey]);

  // OTP path: resolve the agent's 6-digit code to its request, then ingest like a scan/paste.
  const submitCode = async () => {
    setError('');
    setBusy(true);
    try {
      const raw = await lookupAgentRequest(code);
      ingest(raw);
    } catch (e) {
      setError(e.message || 'Could not load the request.');
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id) =>
    setGrantedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // The scope the user actually granted: `login` is implied; every other item is opt-in.
  const approvedScope = () =>
    (req?.scope || []).filter((s) => scopeId(s) === 'login' || grantedIds.has(scopeId(s)));

  const approve = async () => {
    const scope = approvedScope();
    setBusy(true);
    try {
      const r = await issueCapability(userId, masterKey, {
        audience: req.audience,
        scope,
        ttlSeconds: ttl,
        agentPub: req.agentPub,
      });
      setResult(r);
      setPhase('issued');
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
      // Step-up: the new capability supersedes the old one — revoke it if the user kept that on.
      // Best-effort and AFTER delivery, so a revoke hiccup never blocks the fresh capability.
      if (revokePrior && prior.length) {
        for (const p of prior) {
          revokeAgent(userId, masterKey, { jti: p.jti, audience: p.audience }).catch((e) =>
            console.warn('revoke prior capability failed:', e),
          );
        }
      }
      // Opt-in Web Push (Transport ②): register a channel so this agent can ping the wallet for future
      // step-ups. Best-effort + AFTER the capability — a permission denial never blocks authorization.
      let pushEnabled = false;
      if (notify && pushSupported()) {
        try {
          const { channelId } = await enablePushForAudience(masterKey, req.audience, req.agentPub);
          setPushChannelId(channelId);
          pushEnabled = true;
        } catch (e) {
          showToast('Authorized, but enabling notifications failed: ' + (e.message || e), 'error');
        }
      }
      // Record the capability metadata so it shows in "Authorized agents" (revoke + a notifications
      // toggle). After the push step, so `pushEnabled` is recorded in one write. Best-effort.
      recordAgent(masterKey, {
        jti: r.jti,
        audience: req.audience,
        scope,
        exp: r.exp,
        agentPub: req.agentPub,
        pushEnabled,
      }).catch((e) => console.warn('recordAgent failed:', e));
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
              {prior.length ? 'Additional access' : 'Authorize an agent'}
            </h2>
          </div>
          {prior.length ? (
            <p className="text-[14px] text-muted leading-relaxed mb-4">
              You've already authorized an agent for{' '}
              <span className="font-mono text-ink">{req.audience}</span>. It's now requesting more —
              review the new access below. Approving issues a fresh capability; it never receives your
              keys.
            </p>
          ) : (
            <p className="text-[14px] text-muted leading-relaxed mb-4">
              An agent is requesting access to{' '}
              <span className="font-mono text-ink">{req.audience}</span>. It will act for you there
              within this scope until the capability expires — it never receives your keys.
            </p>
          )}
          <div className="text-[12px] uppercase tracking-wide text-faint mb-2">Choose what to allow</div>
          <div className="flex flex-col gap-1.5 mb-5">
            {req.scope.map((s) => {
              const item = typeof s === 'string' ? { id: s } : s;
              const id = item.id;
              const implied = id === 'login';
              const on = implied || grantedIds.has(id);
              const reservedLabel = RESERVED_LABELS[id];
              const rpLabel = req.scopeLabels && req.scopeLabels[id];
              const constraints = formatConstraints(item);
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => !implied && toggle(id)}
                  disabled={implied}
                  aria-pressed={on}
                  className={`flex items-start gap-2.5 text-left rounded-xl border px-3 py-2.5 transition-colors ${
                    on ? 'border-accent/40 bg-accent-soft' : 'border-line hover:border-muted'
                  } ${implied ? 'cursor-default' : ''}`}
                >
                  <span className={`mt-0.5 shrink-0 ${on ? 'text-accent' : 'text-faint'}`}>
                    {on ? <CheckCircle2 size={16} /> : <Circle size={16} />}
                  </span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-1.5">
                      <span className="font-mono text-[12px] text-ink">{id}</span>
                      {!implied &&
                        prior.length > 0 &&
                        (alreadyGranted(item) ? (
                          <span className="text-[10px] uppercase tracking-wide text-faint">already granted</span>
                        ) : (
                          <span className="text-[10px] uppercase tracking-wide text-accent">new</span>
                        ))}
                    </span>
                    {reservedLabel ? (
                      <span className="block text-[12px] text-muted">{reservedLabel}</span>
                    ) : rpLabel ? (
                      <span className="block text-[12px] text-faint">
                        “{rpLabel}” — {req.audience} says this (unverified)
                      </span>
                    ) : null}
                    {constraints && (
                      <span className="block text-[11px] text-faint">{constraints}</span>
                    )}
                  </span>
                </button>
              );
            })}
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
          {prior.length > 0 && (
            <button
              type="button"
              onClick={() => setRevokePrior((v) => !v)}
              aria-pressed={revokePrior}
              className="w-full flex items-center gap-3 text-left mb-6 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
            >
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-medium text-ink">
                  Revoke the previous capability
                </span>
                <span className="block text-[12px] text-muted">
                  The new one replaces it. Leave on unless the old agent should keep working.
                </span>
              </span>
              <span
                className={`shrink-0 w-9 h-5 rounded-full p-0.5 transition-colors ${
                  revokePrior ? 'bg-accent-fill' : 'bg-line'
                }`}
              >
                <span
                  className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                    revokePrior ? 'translate-x-4' : ''
                  }`}
                />
              </span>
            </button>
          )}
          {pushSupported() && agentNotifyAllowed() && (
            <button
              type="button"
              onClick={() => setNotify((v) => !v)}
              aria-pressed={notify}
              className="w-full flex items-center gap-3 text-left mb-6 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
            >
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-medium text-ink">
                  Notify me for this agent's future requests
                </span>
                <span className="block text-[12px] text-muted">
                  Lets it ping you to approve more access later — asks your permission to send notifications.
                </span>
              </span>
              <span
                className={`shrink-0 w-9 h-5 rounded-full p-0.5 transition-colors ${
                  notify ? 'bg-accent-fill' : 'bg-line'
                }`}
              >
                <span
                  className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                    notify ? 'translate-x-4' : ''
                  }`}
                />
              </span>
            </button>
          )}
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={onClose} disabled={busy}>
              Cancel
            </Btn>
            <Btn variant="primary" onClick={approve} disabled={busy || approvedScope().length === 0}>
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
          {pushChannelId && (
            <div className="rounded-xl border border-accent/30 bg-accent-soft px-3.5 py-3 mb-4">
              <p className="text-[13px] text-ink leading-relaxed mb-1">
                Notifications on for this agent. Give it this push channel so it can ping you for future requests:
              </p>
              <code className="block text-[11px] font-mono text-ink break-all">{pushChannelId}</code>
            </div>
          )}
          {delivered && (
            <div className="flex items-center gap-2 text-[13px] text-success mb-4">
              <CheckCircle2 size={15} className="shrink-0" />
              <span>Delivered to the agent — no copying needed. The QR/token below is a backup.</span>
            </div>
          )}
          <div className="flex justify-center mb-4">
            <div ref={qrRef} aria-label="Capability QR" className="rounded-2xl border border-line bg-white p-3" />
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
            scope you approve, without giving it any of your keys. Enter the code the agent shows,
            scan its QR, or paste its request.
          </p>
          <label className="block text-[12px] uppercase tracking-wide text-faint mb-2">
            Enter the 6-digit code
          </label>
          <div className="flex gap-2 mb-4">
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="000000"
              value={code}
              onChange={(e) => {
                setCode(e.target.value.replace(/\D/g, '').slice(0, 6));
                if (error) setError('');
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && code.length === 6 && !busy) submitCode();
              }}
              className="flex-1 min-w-0 rounded-xl border border-line bg-surface px-4 py-3 text-center text-xl font-mono tracking-[0.4em] text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
            />
            <Btn variant="primary" onClick={submitCode} disabled={code.length !== 6 || busy}>
              {busy ? '…' : 'Continue'}
            </Btn>
          </div>
          <Btn variant="quiet" onClick={() => setShowScanner(true)} className="w-full mb-4">
            <ScanLine size={16} /> Scan agent QR
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
