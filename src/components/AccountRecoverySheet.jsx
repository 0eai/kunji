import React, { useState } from 'react';
import { ShieldCheck, Mail, Link2, AlertTriangle, CheckCircle2 } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Field, PasswordField, SheetHeading } from './ui/primitives';
import { verifyPasskey } from '../services/vault';
import { getStrength } from '../lib/passkeyStrength';
import {
  linkedProviders,
  linkGoogle,
  startEmailLink,
  unlinkProvider,
} from '../lib/firebase';
import { useToast } from '../contexts/ToastContext';

// The passkey becomes the SOLE secret protecting a now-remotely-fetchable vault, so
// linking is gated behind a stronger floor than vault creation (which only rejects "Weak").
const STRONG_LABELS = ['Strong', 'Very strong'];

const providerName = (id) => (id === 'google.com' ? 'Google' : id === 'password' ? 'Email' : id);

// Optional account-backed recovery (opt-in). Linking a federated provider makes this
// account's uid stable across devices, so a fresh device can reach the existing
// `users/{uid}` vault doc and unlock it with the normal passkey — no recovery file or
// linked device needed. We confirm the current passkey and require it to be at least
// "Strong" before linking (the passkey is the only thing standing between the linked
// account and the vault). Mirrors the RecoveryKeySheet pattern; no crypto here beyond
// verifyPasskey (derivation lives in services/vault).
const AccountRecoverySheet = ({ userId, onClose }) => {
  const { showToast } = useToast();
  const [providers, setProviders] = useState(() => linkedProviders());
  const [passkey, setPasskey] = useState('');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [emailSent, setEmailSent] = useState(false);

  const isOn = providers.length > 0;
  const strength = getStrength(passkey);

  // Confirm the passkey is correct AND strong enough before linking. Toasts + returns
  // false on any failure. Shared by the Google and email link buttons.
  const passkeyOk = async () => {
    if (!passkey) {
      showToast('Enter your current passkey.', 'error');
      return false;
    }
    if (!STRONG_LABELS.includes(strength.label)) {
      showToast('Strengthen your passkey first (Change passkey) — it’s the only secret protecting a recoverable vault.', 'error');
      return false;
    }
    if (!(await verifyPasskey(userId, passkey))) {
      showToast('That passkey is incorrect.', 'error');
      return false;
    }
    return true;
  };

  const handleLinkGoogle = async () => {
    setBusy(true);
    try {
      if (!(await passkeyOk())) return;
      await linkGoogle();
      setProviders(linkedProviders());
      setPasskey('');
      showToast('Account recovery is on.');
    } catch (e) {
      if (e.code === 'auth/credential-already-in-use' || e.code === 'auth/email-already-in-use') {
        showToast('That Google account already protects another kunji vault. On a new device, use “Recover with account” instead of linking.', 'error');
      } else if (e.code === 'auth/popup-closed-by-user' || e.code === 'auth/cancelled-popup-request') {
        /* user dismissed the popup — no-op */
      } else if (e.code === 'auth/unauthorized-domain') {
        showToast('This domain isn’t authorized for sign-in yet.', 'error');
      } else {
        showToast(e.message || 'Could not link Google.', 'error');
      }
    } finally {
      setBusy(false);
    }
  };

  const handleSendEmail = async () => {
    setBusy(true);
    try {
      if (!email.trim()) {
        showToast('Enter your email.', 'error');
        return;
      }
      if (!(await passkeyOk())) return;
      await startEmailLink(email.trim(), 'link');
      setEmailSent(true);
      setPasskey('');
      showToast('Check your email and tap the link on this device to finish.');
    } catch (e) {
      showToast(e.message || 'Could not send the email link.', 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleUnlink = async (providerId) => {
    setBusy(true);
    try {
      await unlinkProvider(providerId);
      setProviders(linkedProviders());
      showToast('Account recovery turned off for that provider.');
    } catch (e) {
      showToast(e.message || 'Could not unlink.', 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet onClose={() => !busy && onClose()} z={60} labelledBy="recovery-account-title">
      <SheetHeading
        id="recovery-account-title"
        icon={ShieldCheck}
        info="Optional. Link a Google account or email so you can get back into your vault on a brand-new device using only that account and your passkey — no recovery file or other device needed. Your vault stays encrypted: the passkey still decrypts it, and apps still see only your unlinkable per-app identities."
      >
        Account recovery
      </SheetHeading>

      {/* Currently linked providers */}
      {isOn && (
        <div className="mb-6">
          <div className="flex items-center gap-2 text-[13px] text-success mb-3">
            <CheckCircle2 size={15} /> On — you can recover this vault on a new device.
          </div>
          <div className="divide-y divide-line border-y border-line">
            {providers.map((p) => (
              <div key={p.providerId} className="flex items-center gap-3 py-3">
                {p.providerId === 'password' ? (
                  <Mail size={16} className="text-muted shrink-0" />
                ) : (
                  <Link2 size={16} className="text-muted shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="text-[14px] text-ink">{providerName(p.providerId)}</div>
                  {p.email && <div className="text-[12px] text-faint truncate">{p.email}</div>}
                </div>
                <button
                  type="button"
                  onClick={() => handleUnlink(p.providerId)}
                  disabled={busy}
                  className="text-[12px] text-faint hover:text-danger transition-colors disabled:opacity-40"
                >
                  Turn off
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* What linking means — the trade-off, stated plainly (opt-in). */}
      <div className="rounded-xl bg-accent-soft/40 border border-line p-3.5 mb-5 text-[12px] text-muted leading-relaxed">
        <p className="flex items-start gap-2">
          <AlertTriangle size={14} className="text-accent shrink-0 mt-0.5" />
          <span>
            Linking lets kunji associate your account with this (still encrypted) vault, and a
            recovered device <strong className="text-ink font-medium">shares the same passkey</strong>{' '}
            as this one. Your passkey becomes the only secret protecting the vault, so it must be
            strong. Apps still see only your unlinkable per-app identities.
          </span>
        </p>
      </div>

      {/* Confirm passkey (verifies + measures strength) */}
      <PasswordField
        label={isOn ? 'Confirm passkey to add another' : 'Confirm your passkey'}
        value={passkey}
        onChange={(e) => setPasskey(e.target.value)}
        autoFocus
      />
      <div className="h-5 mt-1.5">
        {passkey.length > 0 && (
          <div className="flex justify-between items-center">
            <span
              className={`text-[11px] uppercase tracking-[0.14em] ${
                STRONG_LABELS.includes(strength.label) ? 'text-success' : 'text-accent'
              }`}
            >
              {strength.label || '—'}
              {!STRONG_LABELS.includes(strength.label) && ' · needs to be Strong'}
            </span>
          </div>
        )}
      </div>

      <Btn variant="primary" onClick={handleLinkGoogle} disabled={busy} className="w-full mt-3">
        <Link2 size={16} /> {busy ? 'Working…' : 'Link Google account'}
      </Btn>

      <div className="text-[12px] uppercase tracking-wide text-faint mb-2 mt-7">Or link by email</div>
      <Field
        label="Email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="you@example.com"
      />
      <Btn
        variant="quiet"
        onClick={handleSendEmail}
        disabled={busy || !email.trim()}
        className="w-full mt-3"
      >
        <Mail size={16} /> {emailSent ? 'Resend email link' : 'Send email link'}
      </Btn>
      {emailSent && (
        <p className="text-[12px] text-muted leading-relaxed mt-3">
          We sent a sign-in link to <strong className="text-ink font-medium">{email.trim()}</strong>.
          Open it <strong className="text-ink font-medium">on this device</strong> to finish linking.
        </p>
      )}
    </Sheet>
  );
};

export default AccountRecoverySheet;
