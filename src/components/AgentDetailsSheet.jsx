import React, { useState } from 'react';
import { Copy, CheckCircle2, Bell, BellRing, Trash2, Activity, ChevronRight } from 'lucide-react';
import Sheet from './ui/Sheet';
import { SectionLabel, Monogram, Btn } from './ui/primitives';
import ActivitySheet from './ActivitySheet';
import { scopeId } from '../lib/capability';
import { relTime } from '../lib/activityFormat';
import { expiryLabel, expiryTone } from '../lib/agentFormat';
import { revokeAgent, setAgentPushEnabled } from '../services/capability';
import {
  pushSupported,
  enablePushForAudience,
  revokePushForAudience,
  revokePushAllDevices,
  agentNotifyAllowed,
  isPushOnHere,
} from '../services/push';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';

// Per-agent detail (mirrors AppDetailsModal): the scoped capability's access, the agent's holder key, a
// per-device notifications toggle, recent (lifecycle) activity for this agent, and revoke. Opened from the
// agents list (AgentsSheet today; the Dashboard agents view in Step 2).
const AgentDetailsSheet = ({ agent, userId, masterKey, onClose, onRevoked }) => {
  const { showToast } = useToast();
  const [showActivity, setShowActivity] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [copied, setCopied] = useState(false);
  const supportsPush = pushSupported();
  const globalNotify = agentNotifyAllowed();
  const [onHere, setOnHere] = useState(() => isPushOnHere(agent.audience)); // this device receives?
  const [pushBusy, setPushBusy] = useState(false);

  const copyKey = () => {
    navigator.clipboard.writeText(agent.agentPub || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Per-device notifications: register/remove THIS device's push channel for the agent's audience.
  const toggleNotify = async () => {
    setPushBusy(true);
    try {
      if (onHere) {
        await revokePushForAudience(masterKey, agent.audience);
        setOnHere(false);
        await logActivity(userId, `Turned off agent notifications for ${agent.audience}`, 'info', 'BellOff', masterKey, {
          agentJti: agent.jti,
          agentAudience: agent.audience,
        });
        showToast('Notifications off on this device.');
      } else {
        await enablePushForAudience(masterKey, agent.audience, agent.agentPub);
        await setAgentPushEnabled(masterKey, agent, true);
        setOnHere(true);
        await logActivity(userId, `Turned on agent notifications for ${agent.audience}`, 'success', 'Bell', masterKey, {
          agentJti: agent.jti,
          agentAudience: agent.audience,
        });
        showToast('Notifications on for this device.');
      }
    } catch (e) {
      showToast('Could not change notifications: ' + (e.message || e), 'error');
    } finally {
      setPushBusy(false);
    }
  };

  const doRevoke = async () => {
    setRevoking(true);
    try {
      await revokeAgent(userId, masterKey, { jti: agent.jti, audience: agent.audience });
      if (agent.pushEnabled) await revokePushAllDevices(masterKey, agent.audience).catch(() => {});
      showToast('Agent revoked.');
      onRevoked?.(agent.jti);
      onClose?.();
    } catch (e) {
      showToast('Could not revoke: ' + (e.message || e), 'error');
      setRevoking(false);
    }
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="agentdetail-title">
      <div className="flex items-center gap-3.5 mb-7">
        <Monogram name={agent.audience} seed={agent.audience} size="lg" />
        <div className="min-w-0">
          <h2 id="agentdetail-title" className="text-lg font-semibold tracking-tight truncate">
            {agent.audience}
          </h2>
          <p className="text-[13px] text-muted truncate">Authorized agent</p>
        </div>
      </div>

      {/* Access — scope, expiry, when authorized */}
      <div className="mb-7">
        <SectionLabel
          className="mb-2.5"
          info="A scoped, expiring, holder-of-key capability the agent uses to act for you at this app — never your keys. Revoke any time; apps that honor revocation reject it on the next call."
        >
          Access
        </SectionLabel>
        <div className="divide-y divide-line border-y border-line">
          <div className="flex items-start justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted shrink-0">Scope</span>
            <span className="text-[13px] font-mono text-ink text-right break-all min-w-0">
              {(agent.scope || []).map(scopeId).join(', ') || '—'}
            </span>
          </div>
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">Expires</span>
            <span className={`text-[13px] ${expiryTone(agent.exp)}`}>{expiryLabel(agent.exp) || '—'}</span>
          </div>
          {agent.issuedAt ? (
            <div className="flex items-center justify-between gap-4 py-3.5">
              <span className="text-[13px] text-muted">Authorized</span>
              <span className="text-[13px] text-ink">{relTime({ seconds: agent.issuedAt }) || '—'}</span>
            </div>
          ) : null}
        </div>
      </div>

      {/* Agent key (holder-of-key) */}
      {agent.agentPub && (
        <div className="mb-7">
          <SectionLabel
            className="mb-2.5"
            info="The agent's own public key. The capability is bound to it (holder-of-key), so only this agent can use it — the wallet never holds the agent's private key."
          >
            Agent key
          </SectionLabel>
          <div className="flex items-start gap-3 border-y border-line py-3.5">
            <code className="flex-1 text-[12px] font-mono text-ink break-all leading-relaxed">
              {agent.agentPub}
            </code>
            <button
              onClick={copyKey}
              className="shrink-0 text-muted hover:text-ink transition-colors"
              title="Copy agent key"
            >
              {copied ? <CheckCircle2 size={15} className="text-success" /> : <Copy size={15} />}
            </button>
          </div>
        </div>
      )}

      {/* Per-device notifications (gated on the global switch; per-device, like the push subscription) */}
      {supportsPush && globalNotify && (
        <button
          type="button"
          onClick={toggleNotify}
          disabled={pushBusy}
          aria-pressed={onHere}
          className="w-full flex items-center gap-3 text-left mb-7 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50"
        >
          {onHere ? (
            <BellRing size={18} className="text-accent shrink-0" />
          ) : (
            <Bell size={18} className="text-muted shrink-0" />
          )}
          <span className="min-w-0 flex-1">
            <span className="block text-[13px] font-medium text-ink">
              {onHere ? 'Notifications on (this device)' : 'Turn on notifications'}
            </span>
            <span className="block text-[12px] text-muted">
              Let this agent ping you on this device to approve more access.
            </span>
          </span>
          <span
            className={`shrink-0 w-9 h-5 rounded-full p-0.5 transition-colors ${
              onHere ? 'bg-accent-fill' : 'bg-line'
            }`}
          >
            <span
              className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                onHere ? 'translate-x-4' : ''
              }`}
            />
          </span>
        </button>
      )}

      {/* Actions */}
      <div className="divide-y divide-line border-t border-line">
        <button
          onClick={() => setShowActivity(true)}
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-ink hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
        >
          <Activity size={17} strokeWidth={1.75} className="text-muted" />
          <span className="flex-1 text-[15px] font-medium">Recent activity</span>
          <ChevronRight size={16} strokeWidth={1.75} className="text-faint" />
        </button>
        <button
          onClick={() => setConfirm(true)}
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-danger hover:bg-danger-soft active:opacity-80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30"
        >
          <Trash2 size={17} strokeWidth={1.75} />
          <span className="text-[15px] font-medium">Revoke agent</span>
        </button>
      </div>

      {showActivity && (
        <ActivitySheet
          userId={userId}
          cryptoKey={masterKey}
          agentJti={agent.jti}
          agentLabel={agent.audience}
          onClose={() => setShowActivity(false)}
        />
      )}

      {confirm && (
        <Sheet onClose={() => !revoking && setConfirm(false)} z={70} labelledBy="agentrevoke-title">
          <div className="flex items-center gap-2.5 mb-3">
            <Trash2 size={18} className="text-danger" />
            <h2 id="agentrevoke-title" className="text-lg font-semibold tracking-tight">
              Revoke this agent?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            It will no longer be able to act for you at{' '}
            <span className="font-mono text-ink">{agent.audience}</span> — you'd need to authorize a new
            one. Apps that honor revocation reject it on its next attempt.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setConfirm(false)} disabled={revoking}>
              Cancel
            </Btn>
            <Btn variant="danger" onClick={doRevoke} disabled={revoking}>
              {revoking ? 'Revoking…' : 'Revoke'}
            </Btn>
          </div>
        </Sheet>
      )}
    </Sheet>
  );
};

export default AgentDetailsSheet;
