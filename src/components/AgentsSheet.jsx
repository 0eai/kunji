import React, { useState, useEffect, useCallback } from 'react';
import { Bot, ShieldCheck } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, SheetHeading } from './ui/primitives';
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

// Authorized agents: the active capabilities the user has issued (shared across linked devices, encrypted).
// The list + the global notifications switch + "Authorize an agent" live here; per-agent details (scope,
// notifications, revoke, lifecycle activity) live in AgentDetailsSheet. Mirrors the sheet pattern.
const AgentsSheet = ({ userId, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [agents, setAgents] = useState(null); // null = loading
  const [showAuthorize, setShowAuthorize] = useState(false);
  const [detail, setDetail] = useState(null); // agent open in the detail sheet
  const supportsPush = pushSupported();
  const [globalNotify, setGlobalNotify] = useState(agentNotifyAllowed()); // per-device master switch
  const [globalBusy, setGlobalBusy] = useState(false);

  const refresh = useCallback(() => {
    listAgents(masterKey)
      // Soonest-expiring (and already-expired) first, so what needs attention is on top.
      .then((list) => setAgents([...list].sort((a, b) => (a.exp || Infinity) - (b.exp || Infinity))))
      .catch(() => setAgents([]));
  }, [masterKey]);

  useEffect(() => refresh(), [refresh]);

  // Master switch (per-device, like the push subscription). Off is a kill-switch: drop THIS device's
  // subscription for every audience it receives for (other linked devices keep theirs) and block enabling;
  // on re-allows the per-agent toggles (in the detail sheet). It never auto-enables an agent.
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
      for (const aud of auds) await revokePushForAudience(masterKey, aud).catch(() => {}); // this device only
      setAgentNotifyAllowed(false);
      setGlobalNotify(false);
      showToast(auds.length ? 'Agent notifications off on this device.' : 'Agent notifications off.');
    } finally {
      setGlobalBusy(false);
    }
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="agents-title">
      <SheetHeading
        id="agents-title"
        icon={Bot}
        info="Agents — an AI assistant, script, or service — you've authorized to act for you at an app, within a scope and for a limited time, never holding your keys. Revoke any one to cut it off at apps that honor revocation."
      >
        Authorized agents
      </SheetHeading>

      {(() => {
        const soon = (agents || []).filter((a) => a.exp && a.exp * 1000 - Date.now() < SOON_MS).length;
        return soon ? (
          <p className="text-[12px] text-accent bg-accent-soft border border-line rounded-lg px-3 py-2 mb-4">
            {soon === 1 ? '1 agent is' : `${soon} agents are`} expired or expiring soon — re-authorize to keep access.
          </p>
        ) : null;
      })()}

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

      {agents === null ? (
        <p className="text-[13px] text-faint mb-5">Loading…</p>
      ) : agents.length === 0 ? (
        <p className="text-[13px] text-faint mb-5">No active agents.</p>
      ) : (
        <div className="divide-y divide-line mb-5">
          {agents.map((a) => (
            <AgentRow key={a.jti} agent={a} onOpen={() => setDetail(a)} />
          ))}
        </div>
      )}

      <Btn variant="primary" onClick={() => setShowAuthorize(true)} className="w-full">
        <ShieldCheck size={16} /> Authorize an agent
      </Btn>

      {showAuthorize && (
        <AuthorizeAgentSheet
          userId={userId}
          masterKey={masterKey}
          onClose={() => {
            setShowAuthorize(false);
            refresh(); // a newly-authorized agent should appear in the list
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
            setAgents((list) => (list || []).filter((x) => x.jti !== jti));
            setDetail(null);
          }}
        />
      )}
    </Sheet>
  );
};

export default AgentsSheet;
