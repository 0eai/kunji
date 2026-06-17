import React, { useState, useEffect } from 'react';
import { ShieldCheck, CheckCircle2, Circle, XCircle } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn } from './ui/primitives';
import {
  parsePortfolioRequest,
  issueCapability,
  depositAgentCapability,
  recordAgent,
  revokeAgent,
  listAgents,
} from '../services/capability';
import { scopeId, scopeSatisfies } from '../lib/capability';
import { formatConstraints } from '../lib/scopeFormat';
import { useToast } from '../contexts/ToastContext';

const TTLS = [
  { label: '1 hour', s: 3600 },
  { label: '24 hours', s: 86400 },
  { label: '7 days', s: 604800 },
];

const RESERVED_LABELS = {
  login: 'Sign in as you',
  profile: 'Share your profile (name & avatar)',
  offline_access: 'Act without re-approval until it expires',
};

// Portfolio authorization (4.2): ONE agent asking to act for you at SEVERAL apps in a single approval.
// Each app still gets its own independent, per-app-keyed capability delivered over its own relay session
// — this is purely a batched UX over AuthorizeAgentSheet's single-app flow, so per-app unlinkability is
// preserved. Partial success is surfaced (some apps may fail to mint/deliver without blocking the rest).
const AuthorizePortfolioSheet = ({ userId, masterKey, initialRequest, onClose }) => {
  const { showToast } = useToast();
  const [phase, setPhase] = useState('review'); // review → issued
  const [req, setReq] = useState(null); // { agentPub, transportPub, label?, items:[…] }
  const [parseError, setParseError] = useState('');
  const [included, setIncluded] = useState(() => new Set()); // audiences to authorize (default: all)
  const [grantedByAud, setGrantedByAud] = useState({}); // { [audience]: Set<scopeId> } (login implied)
  const [ttl, setTtl] = useState(3600);
  const [busy, setBusy] = useState(false);
  const [prior, setPrior] = useState({}); // { [audience]: [caps this agent already holds here] }
  const [revokePrior, setRevokePrior] = useState(false);
  const [results, setResults] = useState([]); // [{ audience, ok, delivered?, error? }]

  // Parse the request once. A portfolio request always arrives pre-formed (deep link / scan routed here).
  useEffect(() => {
    try {
      const parsed = parsePortfolioRequest(initialRequest);
      setReq(parsed);
      setIncluded(new Set(parsed.items.map((it) => it.audience))); // default: authorize every app
    } catch {
      setParseError('Not a valid kunji multi-app request.');
    }
  }, [initialRequest]);

  // Step-up awareness: pre-tick scopes this same agent already holds per app, and default to replacing
  // the prior capability when any app already has one (mirrors AuthorizeAgentSheet).
  useEffect(() => {
    if (!req) return;
    let cancelled = false;
    listAgents(masterKey)
      .then((agents) => {
        if (cancelled) return;
        const byAud = {};
        for (const it of req.items) {
          const mine = agents.filter((a) => a.audience === it.audience && a.agentPub === req.agentPub);
          if (mine.length) byAud[it.audience] = mine;
        }
        if (!Object.keys(byAud).length) return;
        setPrior(byAud);
        setRevokePrior(true);
        setGrantedByAud((prev) => {
          const next = { ...prev };
          for (const it of req.items) {
            const held = (byAud[it.audience] || []).flatMap((a) => a.scope || []);
            if (!held.length) continue;
            const set = new Set(next[it.audience] || []);
            for (const s of it.scope) {
              const id = scopeId(s);
              if (id !== 'login' && scopeSatisfies(held, [s])) set.add(id);
            }
            next[it.audience] = set;
          }
          return next;
        });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [req, masterKey]);

  const toggleApp = (audience) =>
    setIncluded((prev) => {
      const next = new Set(prev);
      if (next.has(audience)) next.delete(audience);
      else next.add(audience);
      return next;
    });

  const toggleScope = (audience, id) =>
    setGrantedByAud((prev) => {
      const set = new Set(prev[audience] || []);
      if (set.has(id)) set.delete(id);
      else set.add(id);
      return { ...prev, [audience]: set };
    });

  // The scope actually granted for an app: `login` is implied; every other item is opt-in.
  const approvedScopeFor = (it) =>
    (it.scope || []).filter((s) => scopeId(s) === 'login' || grantedByAud[it.audience]?.has(scopeId(s)));

  const activeItems = () => (req?.items || []).filter((it) => included.has(it.audience));
  const priorCount = Object.keys(prior).length;

  const approve = async () => {
    setBusy(true);
    const out = [];
    for (const it of activeItems()) {
      const scope = approvedScopeFor(it);
      try {
        const r = await issueCapability(userId, masterKey, {
          audience: it.audience,
          scope,
          ttlSeconds: ttl,
          agentPub: req.agentPub,
        });
        // Deliver over the encrypted relay (one shared transport key, this item's own session id).
        let delivered = false;
        try {
          await depositAgentCapability(it.sessionId, req.transportPub, r.capability, it.audience);
          delivered = true;
        } catch (e) {
          console.warn('portfolio relay failed for', it.audience, e);
        }
        // The new capability supersedes any prior one for this app, if the user kept that on. Best-effort.
        if (revokePrior && prior[it.audience]?.length) {
          for (const p of prior[it.audience]) {
            revokeAgent(userId, masterKey, { jti: p.jti, audience: it.audience }).catch((e) =>
              console.warn('revoke prior failed', e),
            );
          }
        }
        // Record metadata so it shows in "Authorized agents" (grouped under this agent's label). Best-effort.
        recordAgent(masterKey, {
          jti: r.jti,
          audience: it.audience,
          scope,
          exp: r.exp,
          agentPub: req.agentPub,
          agentLabel: req.label,
        }).catch((e) => console.warn('recordAgent failed:', e));
        out.push({ audience: it.audience, ok: true, delivered });
      } catch (e) {
        out.push({ audience: it.audience, ok: false, error: e.message || String(e) });
      }
    }
    setResults(out);
    setPhase('issued');
    setBusy(false);
    const failed = out.filter((r) => !r.ok).length;
    if (failed) showToast(`Authorized ${out.length - failed} of ${out.length} apps — ${failed} failed.`, 'error');
  };

  if (parseError) {
    return (
      <Sheet onClose={onClose} z={60} labelledBy="portfolio-title">
        <h2 id="portfolio-title" className="text-lg font-semibold tracking-tight mb-2">
          Couldn't read the request
        </h2>
        <p className="text-[14px] text-muted leading-relaxed mb-5">{parseError}</p>
        <div className="flex justify-end">
          <Btn variant="primary" onClick={onClose}>
            Close
          </Btn>
        </div>
      </Sheet>
    );
  }
  if (!req) return <Sheet onClose={onClose} z={60} labelledBy="portfolio-title" />;

  const agentName = req.label || 'An agent';
  const n = req.items.length;

  return (
    <Sheet onClose={onClose} z={60} labelledBy="portfolio-title">
      {phase === 'review' ? (
        <>
          <div className="flex items-center gap-2.5 mb-1">
            <ShieldCheck size={18} className="text-success" />
            <h2 id="portfolio-title" className="text-lg font-semibold tracking-tight">
              Authorize across {n} app{n === 1 ? '' : 's'}
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            <span className="text-ink font-medium">{agentName}</span> wants to act for you at the apps
            below — each within a scope you approve, until the capability expires. It gets a separate
            capability per app and never receives your keys.
          </p>

          <div className="flex flex-col gap-3 mb-5">
            {req.items.map((it) => {
              const on = included.has(it.audience);
              const hasPrior = !!prior[it.audience]?.length;
              return (
                <div
                  key={it.audience}
                  className={`rounded-xl border transition-colors ${
                    on ? 'border-line' : 'border-line/60 opacity-60'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => toggleApp(it.audience)}
                    aria-pressed={on}
                    className="w-full flex items-center gap-3 px-3.5 py-3 text-left"
                  >
                    <span className={`shrink-0 ${on ? 'text-accent' : 'text-faint'}`}>
                      {on ? <CheckCircle2 size={18} /> : <Circle size={18} />}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[13px] text-ink truncate">{it.audience}</span>
                      {hasPrior && (
                        <span className="block text-[11px] text-faint">already connected — will replace</span>
                      )}
                    </span>
                  </button>
                  {on && (
                    <div className="px-3.5 pb-3 flex flex-col gap-1.5">
                      {it.scope.map((s) => {
                        const item = typeof s === 'string' ? { id: s } : s;
                        const id = item.id;
                        const implied = id === 'login';
                        const granted = implied || grantedByAud[it.audience]?.has(id);
                        const reservedLabel = RESERVED_LABELS[id];
                        const rpLabel = it.scopeLabels && it.scopeLabels[id];
                        const constraints = formatConstraints(item);
                        return (
                          <button
                            key={id}
                            type="button"
                            onClick={() => !implied && toggleScope(it.audience, id)}
                            disabled={implied}
                            aria-pressed={granted}
                            className={`flex items-start gap-2.5 text-left rounded-lg border px-3 py-2 transition-colors ${
                              granted ? 'border-accent/40 bg-accent-soft' : 'border-line hover:border-muted'
                            } ${implied ? 'cursor-default' : ''}`}
                          >
                            <span className={`mt-0.5 shrink-0 ${granted ? 'text-accent' : 'text-faint'}`}>
                              {granted ? <CheckCircle2 size={15} /> : <Circle size={15} />}
                            </span>
                            <span className="min-w-0">
                              <span className="font-mono text-[12px] text-ink">{id}</span>
                              {reservedLabel ? (
                                <span className="block text-[12px] text-muted">{reservedLabel}</span>
                              ) : rpLabel ? (
                                <span className="block text-[12px] text-faint">
                                  “{rpLabel}” — {it.audience} says this (unverified)
                                </span>
                              ) : null}
                              {constraints && <span className="block text-[11px] text-faint">{constraints}</span>}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
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

          {priorCount > 0 && (
            <button
              type="button"
              onClick={() => setRevokePrior((v) => !v)}
              aria-pressed={revokePrior}
              className="w-full flex items-center gap-3 text-left mb-6 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
            >
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-medium text-ink">
                  Replace this agent's previous capabilities
                </span>
                <span className="block text-[12px] text-muted">
                  {priorCount === 1 ? '1 app is' : `${priorCount} apps are`} already connected. Leave on
                  unless the old capability should keep working.
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

          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={onClose} disabled={busy}>
              Cancel
            </Btn>
            <Btn variant="primary" onClick={approve} disabled={busy || included.size === 0}>
              {busy ? 'Authorizing…' : `Authorize ${included.size} app${included.size === 1 ? '' : 's'}`}
            </Btn>
          </div>
        </>
      ) : (
        <>
          <div className="flex items-center gap-2.5 mb-1">
            <ShieldCheck size={18} className="text-success" />
            <h2 id="portfolio-title" className="text-lg font-semibold tracking-tight">
              {results.every((r) => r.ok) ? 'Authorized' : 'Partly authorized'}
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-4">
            Each app got its own scoped, expiring capability, delivered to the agent securely. You can
            review or revoke any of them under Authorized agents.
          </p>
          <div className="divide-y divide-line border-y border-line mb-5">
            {results.map((r) => (
              <div key={r.audience} className="flex items-center gap-3 py-3">
                {r.ok ? (
                  <CheckCircle2 size={16} className="text-success shrink-0" />
                ) : (
                  <XCircle size={16} className="text-danger shrink-0" />
                )}
                <span className="min-w-0 flex-1">
                  <span className="block font-mono text-[12px] text-ink truncate">{r.audience}</span>
                  <span className="block text-[11px] text-faint">
                    {r.ok
                      ? r.delivered
                        ? 'Authorized & delivered'
                        : 'Authorized — delivery pending (the agent can re-poll)'
                      : `Failed — ${r.error}`}
                  </span>
                </span>
              </div>
            ))}
          </div>
          <div className="flex justify-end">
            <Btn variant="primary" onClick={onClose}>
              Done
            </Btn>
          </div>
        </>
      )}
    </Sheet>
  );
};

export default AuthorizePortfolioSheet;
