import React, { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, ArrowLeft } from 'lucide-react';
import { Btn, SectionLabel } from './ui/primitives';
import { listAgents } from '../services/capability';
import {
  pushSupported,
  revokePushForAudience,
  localPushAudiences,
  agentNotifyAllowed,
  setAgentNotifyAllowed,
} from '../services/push';
import { SOON_MS } from '../lib/agentFormat';
import { useToast } from '../contexts/ToastContext';
import AuthorizeAgentSheet from './AuthorizeAgentSheet';
import AgentRow from './AgentRow';
import AgentDetailsSheet from './AgentDetailsSheet';

// The agents list as a Dashboard BODY view (rendered in place of the apps list when the user taps the
// agents chip / Security → Authorized agents). Holds the global notifications switch + "Authorize an agent";
// per-agent details (scope, notifications, revoke, lifecycle activity) live in AgentDetailsSheet. Reports
// its count up so the header chip stays in sync. Renders inside the Dashboard's centered column.
const AgentsView = ({ userId, masterKey, onBack, onCountChange }) => {
  const { showToast } = useToast();
  const [agents, setAgents] = useState(null); // null = loading
  const [showAuthorize, setShowAuthorize] = useState(false);
  const [detail, setDetail] = useState(null);
  const supportsPush = pushSupported();
  const [globalNotify, setGlobalNotify] = useState(agentNotifyAllowed());
  const [globalBusy, setGlobalBusy] = useState(false);

  const refresh = useCallback(() => {
    listAgents(masterKey)
      .then((list) => {
        const sorted = [...list].sort((a, b) => (a.exp || Infinity) - (b.exp || Infinity));
        setAgents(sorted);
        onCountChange?.(sorted.length);
      })
      .catch(() => {
        setAgents([]);
        onCountChange?.(0);
      });
  }, [masterKey, onCountChange]);
  useEffect(() => refresh(), [refresh]);

  // Per-device master switch — off is a kill-switch (drop this device's subs for every audience it receives
  // for; other linked devices keep theirs); on re-allows per-agent toggles (in the detail sheet).
  const toggleGlobalNotify = async () => {
    if (!globalNotify) {
      setAgentNotifyAllowed(true);
      setGlobalNotify(true);
      showToast('Agent notifications on — turn them on per agent.');
      return;
    }
    setGlobalBusy(true);
    try {
      const auds = [...localPushAudiences()];
      for (const aud of auds) await revokePushForAudience(masterKey, aud).catch(() => {});
      setAgentNotifyAllowed(false);
      setGlobalNotify(false);
      showToast(
        auds.length ? 'Agent notifications off on this device.' : 'Agent notifications off.',
      );
    } finally {
      setGlobalBusy(false);
    }
  };

  const soon = (agents || []).filter((a) => a.exp && a.exp * 1000 - Date.now() < SOON_MS).length;

  return (
    // NOTE: the entrance animation (transform) must wrap ONLY the content — a transformed ancestor becomes
    // the containing block for `position: fixed`, which would mis-position the nested sheets. So the sheets
    // render as siblings of the animate-rise div, under this non-transformed wrapper → fixed = viewport.
    <div className="pb-8">
      <div className="animate-rise">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink mb-3 -mt-1 underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded"
        >
          <ArrowLeft size={15} /> Apps
        </button>

        {soon ? (
          <p className="text-[12px] text-accent bg-accent-soft border border-line rounded-lg px-3 py-2 mb-4">
            {soon === 1 ? '1 agent is' : `${soon} agents are`} expired or expiring soon —
            re-authorize to keep access.
          </p>
        ) : null}

        {supportsPush && (
          <button
            type="button"
            onClick={toggleGlobalNotify}
            aria-pressed={globalNotify}
            disabled={globalBusy}
            className="w-full flex items-center gap-3 text-left mb-5 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50"
          >
            <span className="min-w-0 flex-1">
              <span className="block text-[13px] font-medium text-ink">Agent notifications</span>
              <span className="block text-[12px] text-muted">
                {globalNotify
                  ? 'Agents you enable can ping you to approve more access. Turning this off blocks them all on this device.'
                  : 'Off — no agent can notify you on this device. Turn on to enable notifications per agent.'}
              </span>
            </span>
            <span
              className={`shrink-0 w-9 h-5 rounded-full p-0.5 transition-colors ${
                globalNotify ? 'bg-accent-fill' : 'bg-line'
              }`}
            >
              <span
                className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                  globalNotify ? 'translate-x-4' : ''
                }`}
              />
            </span>
          </button>
        )}

        <SectionLabel count={agents?.length} className="pt-1 pb-1">
          Agents
        </SectionLabel>
        {agents === null ? (
          <p className="text-[13px] text-faint py-4">Loading…</p>
        ) : agents.length === 0 ? (
          <p className="text-[15px] text-muted leading-relaxed py-4">
            No active agents. Authorize an AI assistant, script, or service to act for you at an app
            — scoped, expiring, and revocable.
          </p>
        ) : (
          <div className="divide-y divide-line">
            {agents.map((a) => (
              <AgentRow key={a.jti} agent={a} onOpen={() => setDetail(a)} />
            ))}
          </div>
        )}

        <Btn variant="primary" onClick={() => setShowAuthorize(true)} className="w-full mt-6">
          <ShieldCheck size={16} /> Authorize an agent
        </Btn>
      </div>

      {showAuthorize && (
        <AuthorizeAgentSheet
          userId={userId}
          masterKey={masterKey}
          onClose={() => {
            setShowAuthorize(false);
            refresh();
          }}
        />
      )}

      {detail && (
        <AgentDetailsSheet
          agent={detail}
          userId={userId}
          masterKey={masterKey}
          onClose={() => setDetail(null)}
          onRevoked={(jti) => {
            setAgents((list) => {
              const next = (list || []).filter((x) => x.jti !== jti);
              onCountChange?.(next.length);
              return next;
            });
            setDetail(null);
          }}
        />
      )}
    </div>
  );
};

export default AgentsView;
