import React, { useState, useEffect, useRef } from 'react';
import {
  X, KeyRound, Copy, CheckCircle2, AlertTriangle, Smartphone, ScanLine,
  Lock, LogOut, Activity, Unlock, ShieldCheck, ShieldX, RotateCcw, Link as LinkIcon, Unlink, Circle, ChevronDown,
} from 'lucide-react';
import { exportRecoveryKey, resetUserVault } from '../services/vault';
import { completeLink } from '../services/linking';
import { listenToActivityLog } from '../services/activityLog';
import { signOutDevice } from '../lib/firebase';
import QRScannerOverlay from './QRScannerOverlay';
import { useToast } from '../contexts/ToastContext';

const MIN_PASSPHRASE = 8;
const CLEAR_MS = 60000;
const SIGNOUT_CONFIRM = 'SIGN OUT';

// Map stored activity icon names → lucide components.
const ACTIVITY_ICONS = { Unlock, Lock, ShieldCheck, ShieldX, AlertTriangle, Smartphone, Link: LinkIcon, Unlink, RotateCcw, CheckCircle: CheckCircle2 };
const TYPE_COLOR = { success: 'text-green-400', danger: 'text-red-400', info: 'text-gray-400' };

const relTime = (createdAt) => {
  const ms = createdAt?.toMillis ? createdAt.toMillis() : (createdAt?.seconds ? createdAt.seconds * 1000 : null);
  if (!ms) return '';
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

// Collapsible section with an icon + title header (collapsed by default).
const Section = ({ icon: Icon, title, open, onToggle, children }) => (
  <section>
    <button
      onClick={onToggle}
      className="w-full flex items-center gap-2 text-sm font-semibold text-white"
    >
      <Icon size={15} className="text-amber-400" />
      <span className="flex-1 text-left">{title}</span>
      <ChevronDown size={16} className={`text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} />
    </button>
    {open && <div className="mt-3">{children}</div>}
  </section>
);

const SecurityPanel = ({ userId, cryptoKey, onLock, onClose }) => {
  const { showToast } = useToast();

  // Which collapsible sections are open (all collapsed by default).
  const [open, setOpen] = useState({ link: false, recovery: false, activity: false });
  const toggle = (k) => setOpen((o) => ({ ...o, [k]: !o[k] }));

  // Activity log
  const [events, setEvents] = useState([]);
  useEffect(() => {
    const unsub = listenToActivityLog(userId, setEvents, 30, cryptoKey);
    return unsub;
  }, [userId, cryptoKey]);

  // Sign-out confirmation dialog
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

  // Export Recovery Key
  const [passkey, setPasskey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const clearTimer = useRef(null);

  // Link a device
  const [showScanner, setShowScanner] = useState(false);

  useEffect(() => () => clearTimeout(clearTimer.current), []);

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
      clearTimer.current = setTimeout(() => setRecoveryKey(''), CLEAR_MS); // auto-clear
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

  const handleLinkScan = async (raw) => {
    setShowScanner(false);
    try {
      await completeLink(raw, cryptoKey);
      showToast('Device linked — it now shares your identity.');
    } catch (e) {
      const msg = e.message === 'link_expired' ? 'Link QR expired.'
        : e.message === 'invalid_link_qr' ? 'Not a kunji device-link QR.'
        : e.message === 'link_already_used' ? 'That link was already used.'
        : 'Linking failed: ' + e.message;
      showToast(msg, 'error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#18181b] border border-[#27272a] rounded-3xl w-full max-w-sm p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-white">Security</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-[#27272a] transition-colors">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-4">
          {/* Link a device */}
          <Section icon={Smartphone} title="Link a device" open={open.link} onToggle={() => toggle('link')}>
            <p className="text-xs text-gray-500 mb-3">
              Add another device to this identity. On the new device choose “Link from another device”, then scan its QR here.
            </p>
            <button
              onClick={() => setShowScanner(true)}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-semibold transition-colors"
            >
              <ScanLine size={16} /> Scan device QR
            </button>
          </Section>

          <div className="border-t border-[#27272a]" />

          {/* Export recovery key */}
          <Section icon={KeyRound} title="Export recovery key" open={open.recovery} onToggle={() => toggle('recovery')}>
            <p className="text-xs text-gray-500 mb-3">
              A cold backup that restores your vault if you lose every device. Encrypted with a separate passphrase — store the key and passphrase apart.
            </p>

            {!recoveryKey ? (
              <div className="space-y-2">
                <input
                  type="password" value={passkey} onChange={e => setPasskey(e.target.value)}
                  placeholder="Current passkey"
                  className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-600 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none"
                />
                <input
                  type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)}
                  placeholder="Recovery passphrase (min 8)"
                  className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-600 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none"
                />
                <button
                  onClick={handleGenerate} disabled={busy}
                  className="w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-black font-semibold transition-colors"
                >
                  {busy ? 'Generating…' : 'Generate Recovery Key'}
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-800/50 rounded-xl p-3">
                  <AlertTriangle size={14} className="text-amber-400 mt-0.5 flex-shrink-0" />
                  <p className="text-xs text-amber-300">
                    Save this now — it clears in 60s. You also need your recovery passphrase to use it. Store them separately.
                  </p>
                </div>
                <div className="relative">
                  <textarea readOnly value={recoveryKey} rows={4}
                    className="w-full p-2.5 text-xs font-mono bg-black border border-[#27272a] rounded-xl resize-none text-gray-300" />
                  <button onClick={copyKey} className="absolute top-2 right-2 p-1.5 rounded-lg hover:bg-[#27272a] transition-colors" title="Copy">
                    {copied ? <CheckCircle2 size={14} className="text-green-400" /> : <Copy size={14} className="text-gray-500" />}
                  </button>
                </div>
                <button onClick={() => setRecoveryKey('')} className="w-full py-2.5 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white text-sm font-medium transition-colors">
                  Done
                </button>
              </div>
            )}
          </Section>

          <div className="border-t border-[#27272a]" />

          {/* Activity */}
          <Section icon={Activity} title="Recent activity" open={open.activity} onToggle={() => toggle('activity')}>
            {events.length === 0 ? (
              <p className="text-xs text-gray-600">No activity on this device yet.</p>
            ) : (
              <div className="space-y-2 max-h-56 overflow-y-auto">
                {events.map((e) => {
                  const Icon = ACTIVITY_ICONS[e.icon] || Circle;
                  return (
                    <div key={e.id} className="flex items-center gap-3">
                      <Icon size={14} className={`${TYPE_COLOR[e.type] || 'text-gray-400'} flex-shrink-0`} />
                      <span className="text-xs text-gray-300 flex-1 truncate">{e.action}</span>
                      <span className="text-[10px] text-gray-600 flex-shrink-0">{relTime(e.createdAt)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </Section>

          <div className="border-t border-[#27272a]" />

          {/* Session */}
          <section className="space-y-2">
            {onLock && (
              <button
                onClick={() => { onClose(); onLock(); }}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-semibold transition-colors"
              >
                <Lock size={16} /> Lock now
              </button>
            )}
            <button
              onClick={() => { setConfirmText(''); setShowSignOut(true); }}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-red-950/60 hover:bg-red-900/60 border border-red-800 text-red-300 font-semibold transition-colors"
            >
              <LogOut size={16} /> Sign out of this device
            </button>
          </section>
        </div>
      </div>

      {showScanner && (
        <QRScannerOverlay onScan={handleLinkScan} onClose={() => setShowScanner(false)} />
      )}

      {showSignOut && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#18181b] border border-red-900/60 rounded-3xl w-full max-w-sm p-6">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-9 h-9 bg-red-500/15 rounded-full flex items-center justify-center">
                <LogOut size={16} className="text-red-400" />
              </div>
              <h2 className="text-lg font-bold text-white">Sign out of this device?</h2>
            </div>
            <p className="text-sm text-gray-400 mb-4">
              This device will forget your identity. You'll need your <strong className="text-gray-200">recovery key</strong> or
              another <strong className="text-gray-200">linked device</strong> to sign back in. Your registered apps stay synced on your other devices.
            </p>
            <label className="block text-xs text-gray-500 mb-1">Type <span className="font-mono text-gray-300">{SIGNOUT_CONFIRM}</span> to confirm</label>
            <input
              autoFocus value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSignOut(); }}
              placeholder={SIGNOUT_CONFIRM}
              className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-700 focus:ring-2 focus:ring-red-600 focus:border-transparent outline-none mb-4"
            />
            <div className="flex gap-2">
              <button
                onClick={() => setShowSignOut(false)} disabled={signingOut}
                className="flex-1 py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSignOut}
                disabled={signingOut || confirmText.trim().toUpperCase() !== SIGNOUT_CONFIRM}
                className="flex-1 py-3 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold transition-colors"
              >
                {signingOut ? 'Signing out…' : 'Sign out'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityPanel;
