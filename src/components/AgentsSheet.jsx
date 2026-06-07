import React, { useState, useEffect, useCallback } from 'react';
import { Bot, Trash2, ShieldCheck } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Monogram } from './ui/primitives';
import { listAgents, revokeAgent } from '../services/capability';
import { useToast } from '../contexts/ToastContext';
import AuthorizeAgentSheet from './AuthorizeAgentSheet';

const expiryLabel = (expSeconds) => {
  if (!expSeconds) return '';
  const ms = expSeconds * 1000 - Date.now();
  if (ms <= 0) return 'expired';
  const h = Math.round(ms / 3_600_000);
  if (h < 48) return `expires in ${Math.max(1, h)}h`;
  return `expires in ${Math.round(h / 24)}d`;
};

// Authorized agents: the active capabilities the user has issued (shared across linked devices,
// encrypted). Each can be revoked — the wallet signs the revocation with the per-app key and
// publishes it to the kunji denylist that cooperating RPs check. Mirrors the sheet pattern.
const AgentsSheet = ({ userId, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [agents, setAgents] = useState(null); // null = loading
  const [showAuthorize, setShowAuthorize] = useState(false);
  const [revoking, setRevoking] = useState('');

  const refresh = useCallback(() => {
    listAgents(masterKey)
      .then(setAgents)
      .catch(() => setAgents([]));
  }, [masterKey]);

  useEffect(() => refresh(), [refresh]);

  const revoke = async (a) => {
    setRevoking(a.jti);
    try {
      await revokeAgent(userId, masterKey, { jti: a.jti, audience: a.audience });
      showToast('Agent revoked.');
      setAgents((list) => (list || []).filter((x) => x.jti !== a.jti));
    } catch (e) {
      showToast('Could not revoke: ' + (e.message || e), 'error');
    } finally {
      setRevoking('');
    }
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="agents-title">
      <div className="flex items-center gap-2.5 mb-3">
        <Bot size={18} className="text-accent" />
        <h2 id="agents-title" className="text-lg font-semibold tracking-tight">
          Authorized agents
        </h2>
      </div>
      <p className="text-[14px] text-muted leading-relaxed mb-5">
        Agents — an AI assistant, script, or service — you've authorized to act for you at an app,
        within a scope and for a limited time, never holding your keys. Revoke any one to cut it off
        at apps that honor revocation.
      </p>

      {agents === null ? (
        <p className="text-[13px] text-faint mb-5">Loading…</p>
      ) : agents.length === 0 ? (
        <p className="text-[13px] text-faint mb-5">No active agents.</p>
      ) : (
        <div className="divide-y divide-line border-y border-line mb-5">
          {agents.map((a) => (
            <div key={a.jti} className="flex items-center gap-3 py-3">
              <Monogram name={a.audience} seed={a.audience} size="sm" />
              <div className="flex-1 min-w-0">
                <p className="text-[14px] text-ink truncate">{a.audience}</p>
                <p className="text-[11px] text-faint truncate">
                  {(a.scope || []).join(', ')} · {expiryLabel(a.exp)}
                </p>
              </div>
              <button
                onClick={() => revoke(a)}
                disabled={!!revoking}
                className="shrink-0 inline-flex items-center gap-1 text-[13px] font-medium text-danger hover:opacity-80 disabled:opacity-40 transition-opacity"
                title="Revoke"
              >
                <Trash2 size={15} />
                {revoking === a.jti ? 'Revoking…' : 'Revoke'}
              </button>
            </div>
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
    </Sheet>
  );
};

export default AgentsSheet;
