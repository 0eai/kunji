import React, { useState, useEffect, useCallback } from 'react';
import { Bot, Trash2, ShieldCheck, Bell, BellRing } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Monogram, SheetHeading } from './ui/primitives';
import { listAgents, revokeAgent, setAgentPushEnabled } from '../services/capability';
import {
  pushSupported,
  enablePushForAudience,
  revokePushForAudience,
  revokePushAllDevices,
  localPushAudiences,
  agentNotifyAllowed,
  setAgentNotifyAllowed,
} from '../services/push';
import { scopeId } from '../lib/capability';
import { useToast } from '../contexts/ToastContext';
import AuthorizeAgentSheet from './AuthorizeAgentSheet';

const SOON_MS = 48 * 3_600_000; // "expiring soon" window — surfaced for re-authorization
const expiryLabel = (expSeconds) => {
  if (!expSeconds) return '';
  const ms = expSeconds * 1000 - Date.now();
  if (ms <= 0) return 'expired';
  const h = Math.round(ms / 3_600_000);
  if (h < 48) return `expires in ${Math.max(1, h)}h`;
  return `expires in ${Math.round(h / 24)}d`;
};
// Local-only urgency tone (no server tracks expiries — this is a client-side reminder).
const expiryTone = (expSeconds) => {
  if (!expSeconds) return 'text-faint';
  const ms = expSeconds * 1000 - Date.now();
  if (ms <= 0) return 'text-danger';
  if (ms < SOON_MS) return 'text-accent';
  return 'text-faint';
};

// Authorized agents: the active capabilities the user has issued (shared across linked devices,
// encrypted). Each can be revoked — the wallet signs the revocation with the per-app key and
// publishes it to the kunji denylist that cooperating RPs check. Mirrors the sheet pattern.
const AgentsSheet = ({ userId, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [agents, setAgents] = useState(null); // null = loading
  const [showAuthorize, setShowAuthorize] = useState(false);
  const [revoking, setRevoking] = useState('');
  const [pushBusy, setPushBusy] = useState(''); // jti whose notifications toggle is in flight
  const [confirm, setConfirm] = useState(null); // agent pending revoke confirmation
  const supportsPush = pushSupported();
  const [globalNotify, setGlobalNotify] = useState(agentNotifyAllowed()); // per-device master switch
  const [globalBusy, setGlobalBusy] = useState(false);
  // Audiences THIS device receives for (per-device truth; mirrors the localStorage set in push.js so the
  // toggle re-renders). Whether a given agent is "on here" also requires OS permission still granted.
  const [pushHere, setPushHere] = useState(() => new Set(localPushAudiences()));
  const isOnHere = (audience) =>
    pushHere.has(audience) && typeof Notification !== 'undefined' && Notification.permission === 'granted';

  const refresh = useCallback(() => {
    listAgents(masterKey)
      // Soonest-expiring (and already-expired) first, so what needs attention is on top.
      .then((list) => setAgents([...list].sort((a, b) => (a.exp || Infinity) - (b.exp || Infinity))))
      .catch(() => setAgents([]));
  }, [masterKey]);

  useEffect(() => refresh(), [refresh]);

  const revoke = async (a) => {
    setRevoking(a.jti);
    try {
      await revokeAgent(userId, masterKey, { jti: a.jti, audience: a.audience });
      // The agent is gone → tear down its push channel for ALL devices (best-effort) so none can be pinged.
      if (a.pushEnabled) await revokePushAllDevices(masterKey, a.audience).catch(() => {});
      setPushHere((s) => {
        const n = new Set(s);
        n.delete(a.audience);
        return n;
      });
      showToast('Agent revoked.');
      setAgents((list) => (list || []).filter((x) => x.jti !== a.jti));
      return true;
    } catch (e) {
      showToast('Could not revoke: ' + (e.message || e), 'error');
      return false;
    } finally {
      setRevoking('');
    }
  };

  // The master switch (per-device, like the push subscription itself). Off is a kill-switch: drop THIS
  // device's subscription for every audience it receives for (other linked devices keep theirs) and block
  // enabling until it's back on. On just re-allows the per-agent toggles (never auto-enables an agent).
  const toggleGlobalNotify = async () => {
    if (!globalNotify) {
      setAgentNotifyAllowed(true);
      setGlobalNotify(true);
      showToast('Agent notifications on — turn them on per agent below.');
      return;
    }
    setGlobalBusy(true);
    try {
      const auds = [...localPushAudiences()];
      for (const aud of auds) {
        await revokePushForAudience(masterKey, aud).catch(() => {}); // this device only
      }
      setPushHere(new Set());
      setAgentNotifyAllowed(false);
      setGlobalNotify(false);
      showToast(auds.length ? 'Agent notifications off on this device.' : 'Agent notifications off.');
    } finally {
      setGlobalBusy(false);
    }
  };

  // Per-agent, per-DEVICE: on → subscribe + register this device's push channel; off → remove just this
  // device's subscription (other devices the user enabled keep receiving). State of "on" is this device's.
  const toggleNotify = async (a) => {
    setPushBusy(a.jti);
    const wasOnHere = isOnHere(a.audience);
    try {
      if (wasOnHere) {
        await revokePushForAudience(masterKey, a.audience);
        setPushHere((s) => {
          const n = new Set(s);
          n.delete(a.audience);
          return n;
        });
        showToast('Notifications off on this device.');
      } else {
        await enablePushForAudience(masterKey, a.audience, a.agentPub);
        await setAgentPushEnabled(masterKey, a, true); // synced hint: configured on some device
        setPushHere((s) => new Set(s).add(a.audience));
        showToast('Notifications on for this device.');
      }
    } catch (e) {
      showToast((wasOnHere ? 'Could not turn off: ' : 'Could not turn on: ') + (e.message || e), 'error');
    } finally {
      setPushBusy('');
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
                ? 'Agents you enable below can ping you to approve more access. Turning this off blocks them all on this device.'
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
        <div className="divide-y divide-line border-y border-line mb-5">
          {agents.map((a) => (
            <div key={a.jti} className="flex items-center gap-3 py-3">
              <Monogram name={a.audience} seed={a.audience} size="sm" />
              <div className="flex-1 min-w-0">
                <p className="text-[14px] text-ink truncate">{a.audience}</p>
                <p className="text-[11px] text-faint truncate">
                  {(a.scope || []).map(scopeId).join(', ')} ·{' '}
                  <span className={expiryTone(a.exp)}>{expiryLabel(a.exp)}</span>
                </p>
                {supportsPush &&
                  globalNotify &&
                  (() => {
                    const onHere = isOnHere(a.audience);
                    return (
                      <button
                        onClick={() => toggleNotify(a)}
                        disabled={pushBusy === a.jti}
                        className="mt-0.5 inline-flex items-center gap-1 text-[11px] font-medium text-accent hover:opacity-80 transition-opacity disabled:opacity-50"
                        title={
                          onHere
                            ? 'Stop notifications on this device'
                            : 'Receive notifications on this device to approve more access'
                        }
                      >
                        {onHere ? <BellRing size={12} /> : <Bell size={12} />}
                        {pushBusy === a.jti ? '…' : onHere ? 'Notifications on' : 'Turn on notifications'}
                      </button>
                    );
                  })()}
              </div>
              <button
                onClick={() => setConfirm(a)}
                className="shrink-0 inline-flex items-center gap-1 text-[13px] font-medium text-danger hover:opacity-80 transition-opacity"
                title="Revoke"
              >
                <Trash2 size={15} />
                Revoke
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
            setPushHere(new Set(localPushAudiences())); // pick up a just-enabled notification opt-in
          }}
        />
      )}

      {confirm && (
        <Sheet onClose={() => !revoking && setConfirm(null)} z={70} labelledBy="revoke-title">
          <div className="flex items-center gap-2.5 mb-3">
            <Trash2 size={18} className="text-danger" />
            <h2 id="revoke-title" className="text-lg font-semibold tracking-tight">
              Revoke this agent?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            It will no longer be able to act for you at{' '}
            <span className="font-mono text-ink">{confirm.audience}</span> — you'd need to authorize a
            new one. Apps that honor revocation reject it on its next attempt.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setConfirm(null)} disabled={!!revoking}>
              Cancel
            </Btn>
            <Btn
              variant="danger"
              onClick={async () => {
                if (await revoke(confirm)) setConfirm(null);
              }}
              disabled={!!revoking}
            >
              {revoking ? 'Revoking…' : 'Revoke'}
            </Btn>
          </div>
        </Sheet>
      )}
    </Sheet>
  );
};

export default AgentsSheet;
