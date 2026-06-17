import React, { useState } from 'react';
import { ChevronRight, ChevronDown, Bot, Trash2 } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn } from './ui/primitives';
import AgentRow from './AgentRow';
import { expiryLabel, expiryTone } from '../lib/agentFormat';
import { revokeAgent } from '../services/capability';
import { revokePushAllDevices } from '../services/push';
import { useToast } from '../contexts/ToastContext';

// A grouped agents entry (4.2): the SAME agent (one agentPub) authorized at several apps via a portfolio
// request shows as one expandable row — "[label] · N apps" — that expands to the per-app AgentRows (each
// still opens its own detail sheet + is independently revocable) plus a "Revoke all" that loops over them.
// Purely a display grouping; the underlying records stay per-jti.
const AgentGroupRow = ({ agents, label, userId, masterKey, onOpen, onRevokedGroup }) => {
  const { showToast } = useToast();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [revoking, setRevoking] = useState(false);

  const apps = new Set(agents.map((a) => a.audience)).size;
  // Soonest expiry across the group, for the collapsed subtitle.
  const soonest = agents.reduce((min, a) => (a.exp && (!min || a.exp < min) ? a.exp : min), null);

  const revokeAll = async () => {
    setRevoking(true);
    try {
      for (const a of agents) {
        await revokeAgent(userId, masterKey, { jti: a.jti, audience: a.audience });
        if (a.pushEnabled) await revokePushAllDevices(masterKey, a.audience).catch(() => {});
      }
      showToast(`Revoked ${agents.length} capabilit${agents.length === 1 ? 'y' : 'ies'}.`);
      onRevokedGroup?.();
    } catch (e) {
      showToast('Could not revoke all: ' + (e.message || e), 'error');
      setRevoking(false);
    }
  };

  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-[calc(100%_+_1.5rem)] flex items-center gap-4 py-4 px-3 -mx-3 rounded-xl text-left group transition-colors
          hover:bg-line/40 active:bg-line/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
      >
        <span className="shrink-0 w-9 h-9 rounded-full bg-accent-soft text-accent flex items-center justify-center">
          <Bot size={18} strokeWidth={1.75} />
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-[15px] font-medium text-ink truncate">{label || 'Agent'}</p>
          <p className="text-[13px] text-muted truncate">
            {apps} app{apps === 1 ? '' : 's'} ·{' '}
            <span className={expiryTone(soonest)}>{expiryLabel(soonest)}</span>
          </p>
        </div>
        {open ? (
          <ChevronDown size={18} strokeWidth={1.75} className="text-faint shrink-0" />
        ) : (
          <ChevronRight size={18} strokeWidth={1.75} className="text-faint shrink-0" />
        )}
      </button>

      {open && (
        <div className="pl-4 ml-2 border-l border-line">
          <div className="divide-y divide-line">
            {agents.map((a) => (
              <AgentRow key={a.jti} agent={a} onOpen={() => onOpen(a)} />
            ))}
          </div>
          <button
            onClick={() => setConfirm(true)}
            className="mt-1 mb-2 inline-flex items-center gap-1.5 text-[13px] text-danger hover:underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30 rounded"
          >
            <Trash2 size={14} /> Revoke all
          </button>
        </div>
      )}

      {confirm && (
        <Sheet onClose={() => !revoking && setConfirm(false)} z={70} labelledBy="grouprevoke-title">
          <div className="flex items-center gap-2.5 mb-3">
            <Trash2 size={18} className="text-danger" />
            <h2 id="grouprevoke-title" className="text-lg font-semibold tracking-tight">
              Revoke all {agents.length} capabilities?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            <span className="text-ink font-medium">{label || 'This agent'}</span> will no longer be able to
            act for you at any of these apps. Apps that honor revocation reject it on the next attempt.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setConfirm(false)} disabled={revoking}>
              Cancel
            </Btn>
            <Btn variant="danger" onClick={revokeAll} disabled={revoking}>
              {revoking ? 'Revoking…' : 'Revoke all'}
            </Btn>
          </div>
        </Sheet>
      )}
    </div>
  );
};

export default AgentGroupRow;
