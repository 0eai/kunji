import React, { useState, useEffect, useRef } from 'react';
import {
  KeyRound,
  Copy,
  CheckCircle2,
  AlertTriangle,
  Smartphone,
  Lock,
  LogOut,
  Activity,
  ChevronRight,
  UserCircle,
  Bot,
} from 'lucide-react';
import { exportRecoveryKey, resetUserVault, changePasskey } from '../services/vault';
import { listenToActivityLog, logActivity } from '../services/activityLog';
import { getStrength, MIN_PASSKEY_LENGTH } from '../lib/passkeyStrength';
import { signOutDevice } from '../lib/firebase';
import { getThemePref, setThemePref } from '../lib/theme';
import { activityIcon, TYPE_COLOR, relTime } from '../lib/activityFormat';
import InstallButton from './InstallButton';
import ProfileSettings from './ProfileSettings';
import IssueLinkSheet from './IssueLinkSheet';
import AuthorizeAgentSheet from './AuthorizeAgentSheet';
import Sheet from './ui/Sheet';
import { SectionLabel, Field, PasswordField, Btn } from './ui/primitives';
import { useToast } from '../contexts/ToastContext';

const MIN_PASSPHRASE = 8;
const CLEAR_MS = 60000;
const SIGNOUT_CONFIRM = 'SIGN OUT';

// Navigable hairline row that expands in place. Optional `count` shows a badge so you
// can see there's content (e.g. activity) without expanding.
const Row = ({ icon: Icon, title, count, open, onToggle, children }) => (
  <div>
    <button
      onClick={onToggle}
      className="w-full flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left group transition-colors
        hover:bg-line/40 active:bg-line/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
    >
      <Icon size={17} strokeWidth={1.75} className="text-muted shrink-0" />
      <span className="flex-1 text-[15px] font-medium text-ink">{title}</span>
      {count != null && (
        <span className="text-[12px] font-mono text-faint tabular">· {count}</span>
      )}
      <ChevronRight
        size={17}
        strokeWidth={1.75}
        className={`text-faint group-hover:text-muted transition-transform ${open ? 'rotate-90' : ''}`}
      />
    </button>
    {open && <div className="pb-5 -mt-1">{children}</div>}
  </div>
);

const SecurityPanel = ({ userId, cryptoKey, onLock, onClose }) => {
  const { showToast } = useToast();

  const [open, setOpen] = useState({
    profile: false,
    changekey: false,
    link: false,
    agent: false,
    recovery: false,
    activity: false,
  });
  const toggle = (k) => setOpen((o) => ({ ...o, [k]: !o[k] }));

  const [theme, setTheme] = useState(getThemePref());

  const [events, setEvents] = useState([]);
  useEffect(() => {
    const unsub = listenToActivityLog(userId, setEvents, 30, cryptoKey);
    return unsub;
  }, [userId, cryptoKey]);

  const [showSignOut, setShowSignOut] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [signingOut, setSigningOut] = useState(false);

  const handleSignOut = async () => {
    if (confirmText.trim().toUpperCase() !== SIGNOUT_CONFIRM) return;
    setSigningOut(true);
    try {
      await resetUserVault(userId);
      await signOutDevice();
      window.location.reload();
    } catch (e) {
      showToast('Sign out failed: ' + e.message, 'error');
      setSigningOut(false);
    }
  };

  const [passkey, setPasskey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const clearTimer = useRef(null);

  const [showIssue, setShowIssue] = useState(false); // issuer sheet (show QR + code to the new device)
  const [showAgent, setShowAgent] = useState(false); // authorize-an-agent (capability) sheet

  const [curKey, setCurKey] = useState('');
  const [newKey, setNewKey] = useState('');
  const [newKey2, setNewKey2] = useState('');
  const [changing, setChanging] = useState(false);

  useEffect(() => () => clearTimeout(clearTimer.current), []);

  const handleChangePasskey = async () => {
    if (newKey.length < MIN_PASSKEY_LENGTH) {
      showToast(`New passkey must be at least ${MIN_PASSKEY_LENGTH} characters.`, 'error');
      return;
    }
    if (getStrength(newKey).label === 'Weak') {
      showToast('Choose a stronger passkey.', 'error');
      return;
    }
    if (newKey !== newKey2) {
      showToast('New passkeys do not match.', 'error');
      return;
    }
    setChanging(true);
    try {
      await changePasskey(userId, cryptoKey, curKey, newKey);
      logActivity(userId, 'Passkey changed', 'success', 'Lock', cryptoKey);
      showToast('Passkey updated.');
      setCurKey('');
      setNewKey('');
      setNewKey2('');
      setOpen((o) => ({ ...o, changekey: false }));
    } catch (e) {
      showToast(e.message || 'Could not change passkey.', 'error');
    } finally {
      setChanging(false);
    }
  };

  const handleGenerate = async () => {
    if (passkey.length < MIN_PASSPHRASE || passphrase.length < MIN_PASSPHRASE) {
      showToast('Passkey and recovery passphrase must be at least 8 characters.', 'error');
      return;
    }
    setBusy(true);
    try {
      const key = await exportRecoveryKey(userId, passkey, passphrase);
      setRecoveryKey(key);
      setPasskey('');
      setPassphrase('');
      clearTimeout(clearTimer.current);
      clearTimer.current = setTimeout(() => setRecoveryKey(''), CLEAR_MS);
    } catch (e) {
      showToast(e.message || 'Failed to generate recovery key.', 'error');
    } finally {
      setBusy(false);
    }
  };

  const copyKey = () => {
    navigator.clipboard.writeText(recoveryKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Sheet onClose={onClose} labelledBy="security-title">
      <h2 id="security-title" className="text-lg font-semibold tracking-tight mb-5">
        Security
      </h2>

      <SectionLabel className="mb-1">Identity</SectionLabel>
      <div className="divide-y divide-line border-y border-line">
        <Row
          icon={UserCircle}
          title="Profile"
          open={open.profile}
          onToggle={() => toggle('profile')}
        >
          <ProfileSettings userId={userId} cryptoKey={cryptoKey} />
        </Row>

        <Row
          icon={Lock}
          title="Change passkey"
          open={open.changekey}
          onToggle={() => toggle('changekey')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Set a new passkey for this device. Your recovery key and any other linked devices keep
            their own passkeys — only this device changes.
          </p>
          <div className="space-y-4">
            <PasswordField
              label="Current passkey"
              value={curKey}
              onChange={(e) => setCurKey(e.target.value)}
            />
            <div>
              <PasswordField
                label={`New passkey (min ${MIN_PASSKEY_LENGTH})`}
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
              />
              {newKey && (
                <div className="mt-2">
                  <div className="h-1 rounded-full bg-line overflow-hidden">
                    <div
                      className={`h-full ${getStrength(newKey).color} transition-all`}
                      style={{ width: getStrength(newKey).width }}
                    />
                  </div>
                  <p className="text-[11px] text-muted mt-1">{getStrength(newKey).label}</p>
                </div>
              )}
            </div>
            <PasswordField
              label="Confirm new passkey"
              value={newKey2}
              onChange={(e) => setNewKey2(e.target.value)}
            />
            <div className="pt-1">
              <Btn
                variant="primary"
                onClick={handleChangePasskey}
                disabled={changing || !curKey || !newKey || !newKey2}
                className="w-full"
              >
                {changing ? 'Updating…' : 'Update passkey'}
              </Btn>
            </div>
          </div>
        </Row>

        <Row
          icon={Smartphone}
          title="Link a device"
          open={open.link}
          onToggle={() => toggle('link')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Add another device to this identity. This device shows a QR and a code; on the new
            device choose “Link this device” and scan or enter it.
          </p>
          <Btn variant="primary" onClick={() => setShowIssue(true)} className="w-full">
            <Smartphone size={16} /> Show link code
          </Btn>
        </Row>

        <Row
          icon={Bot}
          title="Authorize an agent"
          open={open.agent}
          onToggle={() => toggle('agent')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Let an AI agent act for you at one app, within a scope you approve and for a limited time
            — without giving it any of your keys.
          </p>
          <Btn variant="primary" onClick={() => setShowAgent(true)} className="w-full">
            <Bot size={16} /> Authorize an agent
          </Btn>
        </Row>

        <Row
          icon={KeyRound}
          title="Export recovery key"
          open={open.recovery}
          onToggle={() => toggle('recovery')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            A cold backup that restores your vault if you lose every device. Encrypted with a
            separate passphrase — store the key and passphrase apart.
          </p>
          {!recoveryKey ? (
            <div className="space-y-4">
              <PasswordField
                label="Current passkey"
                value={passkey}
                onChange={(e) => setPasskey(e.target.value)}
              />
              <PasswordField
                label="Recovery passphrase (min 8)"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
              />
              <div className="pt-1">
                <Btn variant="primary" onClick={handleGenerate} disabled={busy} className="w-full">
                  {busy ? 'Generating…' : 'Generate recovery key'}
                </Btn>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-start gap-2 text-[13px] text-accent">
                <AlertTriangle size={15} className="mt-0.5 shrink-0" />
                <p>
                  Save this now — it clears in 60s. You also need your recovery passphrase to use
                  it. Store them separately.
                </p>
              </div>
              <div className="flex items-start gap-3 border-y border-line py-3.5">
                <code className="flex-1 text-[12px] font-mono text-ink break-all leading-relaxed tabular">
                  {recoveryKey}
                </code>
                <button
                  onClick={copyKey}
                  className="shrink-0 text-muted hover:text-ink transition-colors"
                  title="Copy"
                >
                  {copied ? (
                    <CheckCircle2 size={15} className="text-success" />
                  ) : (
                    <Copy size={15} />
                  )}
                </button>
              </div>
              <Btn variant="quiet" onClick={() => setRecoveryKey('')} className="w-full">
                Done
              </Btn>
            </div>
          )}
        </Row>

        <Row
          icon={Activity}
          title="Recent activity"
          count={events.length || null}
          open={open.activity}
          onToggle={() => toggle('activity')}
        >
          {events.length === 0 ? (
            <p className="text-[13px] text-faint">No activity on this device yet.</p>
          ) : (
            <div className="divide-y divide-line border-t border-line max-h-64 overflow-y-auto">
              {events.map((e) => {
                const Icon = activityIcon(e.icon);
                return (
                  <div key={e.id} className="flex items-center gap-3 py-3">
                    <Icon size={14} className={`${TYPE_COLOR[e.type] || 'text-muted'} shrink-0`} />
                    <span className="text-[13px] text-ink flex-1 truncate">{e.action}</span>
                    <span className="text-[11px] font-mono text-faint shrink-0 tabular">
                      {relTime(e.createdAt)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </Row>
      </div>

      {/* Appearance */}
      <SectionLabel className="mt-7 mb-3">Appearance</SectionLabel>
      <div className="flex gap-1 p-1 rounded-full border border-line w-fit">
        {['light', 'dark', 'system'].map((opt) => (
          <button
            key={opt}
            onClick={() => {
              setThemePref(opt);
              setTheme(opt);
            }}
            className={`px-4 py-1.5 rounded-full text-[13px] font-medium capitalize transition-colors ${
              theme === opt ? 'bg-accent-soft text-accent' : 'text-muted hover:text-ink'
            }`}
          >
            {opt}
          </button>
        ))}
      </div>

      {/* Session */}
      <SectionLabel className="mt-7 mb-1">This device</SectionLabel>
      <div className="divide-y divide-line border-y border-line">
        <InstallButton variant="row" />
        {onLock && (
          <button
            onClick={() => {
              onClose();
              onLock();
            }}
            className="w-full flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-ink hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <Lock size={17} strokeWidth={1.75} className="text-muted" />{' '}
            <span className="text-[15px] font-medium">Lock now</span>
          </button>
        )}
        <button
          onClick={() => {
            setConfirmText('');
            setShowSignOut(true);
          }}
          className="w-full flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-danger hover:bg-danger-soft active:opacity-80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30"
        >
          <LogOut size={17} strokeWidth={1.75} />{' '}
          <span className="text-[15px] font-medium">Sign out of this device</span>
        </button>
      </div>

      {showIssue && (
        <IssueLinkSheet
          masterKey={cryptoKey}
          userId={userId}
          onClose={() => setShowIssue(false)}
        />
      )}

      {showAgent && (
        <AuthorizeAgentSheet
          userId={userId}
          masterKey={cryptoKey}
          onClose={() => setShowAgent(false)}
        />
      )}

      {showSignOut && (
        <Sheet
          onClose={() => !signingOut && setShowSignOut(false)}
          z={60}
          labelledBy="signout-title"
        >
          <div className="flex items-center gap-2.5 mb-3">
            <LogOut size={18} className="text-danger" />
            <h2 id="signout-title" className="text-lg font-semibold tracking-tight">
              Sign out of this device?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            This device will forget your identity. You'll need your{' '}
            <strong className="text-ink font-medium">recovery key</strong> or another{' '}
            <strong className="text-ink font-medium">linked device</strong> to sign back in. Your
            registered apps stay synced on your other devices.
          </p>
          <label className="block text-[11px] uppercase tracking-[0.14em] text-faint mb-1">
            Type <span className="font-mono normal-case text-muted">{SIGNOUT_CONFIRM}</span> to
            confirm
          </label>
          <Field
            autoFocus
            value={confirmText}
            mono
            onChange={(e) => setConfirmText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSignOut();
            }}
            placeholder={SIGNOUT_CONFIRM}
            className="mb-6"
          />
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setShowSignOut(false)} disabled={signingOut}>
              Cancel
            </Btn>
            <Btn
              variant="danger"
              onClick={handleSignOut}
              disabled={signingOut || confirmText.trim().toUpperCase() !== SIGNOUT_CONFIRM}
            >
              {signingOut ? 'Signing out…' : 'Sign out'}
            </Btn>
          </div>
        </Sheet>
      )}
    </Sheet>
  );
};

export default SecurityPanel;
