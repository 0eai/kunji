import React, { useState, useEffect, useCallback } from 'react';
import {
  KeyRound,
  Smartphone,
  Lock,
  LogOut,
  Activity,
  ChevronRight,
  UserCircle,
  Bot,
  BadgeCheck,
  ShieldCheck,
} from 'lucide-react';
import { resetUserVault } from '../services/vault';
import { signOutDevice, hasAccountRecovery } from '../lib/firebase';
import { getThemePref, setThemePref } from '../lib/theme';
import InstallButton from './InstallButton';
import LinkedDevicesSheet from './LinkedDevicesSheet';
import CredentialsSheet from './CredentialsSheet';
import ChangePasskeySheet from './ChangePasskeySheet';
import ProfileSheet from './ProfileSheet';
import RecoveryKeySheet from './RecoveryKeySheet';
import AccountRecoverySheet from './AccountRecoverySheet';
import ActivitySheet from './ActivitySheet';
import Sheet from './ui/Sheet';
import { SectionLabel, Field, Btn } from './ui/primitives';
import { listAgents } from '../services/capability';
import { listCredentials } from '../services/credentials';
import { useToast } from '../contexts/ToastContext';

const SIGNOUT_CONFIRM = 'SIGN OUT';

// Navigable hairline row that expands in place. Optional `count` shows a badge so you
// can see there's content without expanding.
const Row = ({ icon: Icon, title, count, open, onToggle, children }) => (
  <div>
    <button
      onClick={onToggle}
      className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left group transition-colors
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

const SecurityPanel = ({ userId, cryptoKey, onLock, onManageAgents, onClose }) => {
  const { showToast } = useToast();

  const [open, setOpen] = useState({
    profile: false,
    changekey: false,
    link: false,
    agent: false,
    credentials: false,
    recovery: false,
    accountRecovery: false,
    activity: false,
  });
  // Single-open accordion: expanding one row collapses the rest; re-clicking closes it.
  const toggle = (k) => setOpen((o) => ({ [k]: !o[k] }));

  const [theme, setTheme] = useState(getThemePref());

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

  const [showDevices, setShowDevices] = useState(false); // linked-devices list (wraps the issuer flow)

  // Active-agents count for the row badge — listAgents already drops expired ones.
  const [agentCount, setAgentCount] = useState(0);
  const refreshAgents = useCallback(() => {
    listAgents(cryptoKey)
      .then((a) => setAgentCount(a.length))
      .catch(() => setAgentCount(0));
  }, [cryptoKey]);
  useEffect(() => {
    if (cryptoKey) refreshAgents();
  }, [cryptoKey, refreshAgents]);

  const [showCredentials, setShowCredentials] = useState(false); // verified-credentials sheet
  const [credentialCount, setCredentialCount] = useState(0);
  const refreshCredentials = useCallback(() => {
    listCredentials(cryptoKey)
      .then((c) => setCredentialCount(c.length))
      .catch(() => setCredentialCount(0));
  }, [cryptoKey]);
  useEffect(() => {
    if (cryptoKey) refreshCredentials();
  }, [cryptoKey, refreshCredentials]);
  const [showChangeKey, setShowChangeKey] = useState(false); // change-passkey sheet
  const [showProfile, setShowProfile] = useState(false); // edit-profile sheet
  const [showRecovery, setShowRecovery] = useState(false); // export-recovery-key sheet
  const [showAccountRecovery, setShowAccountRecovery] = useState(false); // account-recovery (provider link) sheet
  // Re-read on each render so it reflects a just-linked/unlinked provider; cheap (reads auth.currentUser).
  const accountRecoveryOn = hasAccountRecovery();
  const [showActivity, setShowActivity] = useState(false); // recent-activity sheet

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
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Set an optional custom name and photo to share, per app, when one asks. Off by default —
            apps otherwise see a random, unlinkable identity.
          </p>
          <Btn variant="primary" onClick={() => setShowProfile(true)} className="w-full">
            <UserCircle size={16} /> Edit profile
          </Btn>
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
          <Btn variant="primary" onClick={() => setShowChangeKey(true)} className="w-full">
            <Lock size={16} /> Change passkey
          </Btn>
        </Row>

        <Row
          icon={Smartphone}
          title="Linked devices"
          open={open.link}
          onToggle={() => toggle('link')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            See the devices that hold this identity, and add a new one — it shows a QR and a code; on
            the new device choose “Link this device” and scan or enter it.
          </p>
          <Btn variant="primary" onClick={() => setShowDevices(true)} className="w-full">
            <Smartphone size={16} /> Manage devices
          </Btn>
        </Row>

        <Row
          icon={Bot}
          title="Authorized agents"
          count={agentCount || undefined}
          open={open.agent}
          onToggle={() => toggle('agent')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Agents you've authorized to act for you at an app — within a scope and for a limited
            time, never holding your keys. Review them and revoke any one.
          </p>
          <Btn variant="primary" onClick={onManageAgents} className="w-full">
            <Bot size={16} /> Manage agents
          </Btn>
        </Row>

        <Row
          icon={BadgeCheck}
          title="Verified credentials"
          count={credentialCount || undefined}
          open={open.credentials}
          onToggle={() => toggle('credentials')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Credentials from trusted issuers (like an over-18 proof). Present one when an app asks —
            revealing only what's asked, never your date of birth.
          </p>
          <Btn variant="primary" onClick={() => setShowCredentials(true)} className="w-full">
            <BadgeCheck size={16} /> Manage credentials
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
          <Btn variant="primary" onClick={() => setShowRecovery(true)} className="w-full">
            <KeyRound size={16} /> Export recovery key
          </Btn>
        </Row>

        <Row
          icon={ShieldCheck}
          title="Account recovery"
          count={accountRecoveryOn ? 'on' : undefined}
          open={open.accountRecovery}
          onToggle={() => toggle('accountRecovery')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Optional. Link a Google account or email so you can get back into your vault on a brand-new
            device using only that account and your passkey — no recovery file or other device needed.
            Your vault stays encrypted and apps still see only your unlinkable per-app identities.
          </p>
          <Btn variant="primary" onClick={() => setShowAccountRecovery(true)} className="w-full">
            <ShieldCheck size={16} /> {accountRecoveryOn ? 'Manage account recovery' : 'Set up account recovery'}
          </Btn>
        </Row>

        <Row
          icon={Activity}
          title="Recent activity"
          open={open.activity}
          onToggle={() => toggle('activity')}
        >
          <p className="text-[13px] text-muted leading-relaxed mb-4">
            Sign-ins, approvals, and security events recorded on this device.
          </p>
          <Btn variant="primary" onClick={() => setShowActivity(true)} className="w-full">
            <Activity size={16} /> View activity
          </Btn>
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
            className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-ink hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
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
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-danger hover:bg-danger-soft active:opacity-80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30"
        >
          <LogOut size={17} strokeWidth={1.75} />{' '}
          <span className="text-[15px] font-medium">Sign out of this device</span>
        </button>
      </div>

      {showDevices && (
        <LinkedDevicesSheet
          masterKey={cryptoKey}
          userId={userId}
          onClose={() => setShowDevices(false)}
        />
      )}


      {showCredentials && (
        <CredentialsSheet
          masterKey={cryptoKey}
          onClose={() => {
            setShowCredentials(false);
            refreshCredentials();
          }}
        />
      )}

      {showChangeKey && (
        <ChangePasskeySheet
          userId={userId}
          masterKey={cryptoKey}
          onClose={() => setShowChangeKey(false)}
        />
      )}

      {showProfile && (
        <ProfileSheet userId={userId} cryptoKey={cryptoKey} onClose={() => setShowProfile(false)} />
      )}

      {showRecovery && (
        <RecoveryKeySheet userId={userId} onClose={() => setShowRecovery(false)} />
      )}

      {showAccountRecovery && (
        <AccountRecoverySheet userId={userId} onClose={() => setShowAccountRecovery(false)} />
      )}

      {showActivity && (
        <ActivitySheet
          userId={userId}
          cryptoKey={cryptoKey}
          onClose={() => setShowActivity(false)}
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
