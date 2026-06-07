import React, { useState, useRef, useEffect, lazy, Suspense } from 'react';
import { ArrowLeft, ShieldCheck, ScanLine } from 'lucide-react';
import {
  parseLinkQR,
  resolveLinkCode,
  submitPeerKey,
  watchForLinkedKey,
} from '../services/linking';
import { provisionVaultFromMasterKey } from '../services/vault';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';
import { PasswordField, Btn, Spinner } from './ui/primitives';

const QRScannerOverlay = lazy(() => import('./QRScannerOverlay'));
const MIN_PASSKEY_LENGTH = 10;

const errText = (msg) =>
  msg === 'link_expired' || msg === 'expired_code'
    ? 'That code expired — start again on your other device.'
    : msg === 'link_already_used'
      ? 'That link was already used.'
      : msg === 'invalid_code'
        ? 'That code is wrong or expired.'
        : msg === 'rate_limited'
          ? 'Too many attempts. Wait a minute.'
          : msg === 'invalid_link_qr'
            ? 'Not a kunji device-link QR.'
            : msg === 'link_not_found'
              ? 'That link is no longer available.'
              : 'Linking failed: ' + msg;

// Device B (new device): consume the issuer's QR or code, confirm the shared code (SAS)
// matches the other device, receive the vault master key, and set a local passkey.
const LinkDeviceScreen = ({ user, onUnlock, onCancel }) => {
  const { showToast } = useToast();
  const [phase, setPhase] = useState('choose'); // choose → verify → received → saving
  const [showScanner, setShowScanner] = useState(false);
  const [codeInput, setCodeInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [sas, setSas] = useState('');
  const [passkey, setPasskey] = useState('');
  const [confirmKey, setConfirmKey] = useState('');
  const masterKeyRef = useRef(null);
  const unsubRef = useRef(null);

  useEffect(() => () => unsubRef.current?.(), []);

  // With {linkId, pubA} in hand: publish our key, show the SAS, and wait for the deposit.
  const proceed = async ({ linkId, pubA }) => {
    setBusy(true);
    setError('');
    try {
      const { privateKey, sas: sasCode } = await submitPeerKey(linkId, pubA);
      setSas(sasCode);
      setPhase('verify');
      unsubRef.current = watchForLinkedKey(
        linkId,
        privateKey,
        pubA,
        (masterKey) => {
          masterKeyRef.current = masterKey;
          unsubRef.current?.();
          setPhase('received');
        },
        () => showToast('Could not decrypt the linked key. Try again.', 'error'),
      );
    } catch (e) {
      setError(errText(e.message));
      setPhase('choose');
    } finally {
      setBusy(false);
    }
  };

  const handleScan = async (raw) => {
    setShowScanner(false);
    try {
      await proceed(parseLinkQR(raw));
    } catch (e) {
      setError(errText(e.message));
    }
  };

  const submitCode = async () => {
    if (!/^\d{8}$/.test(codeInput)) {
      setError('Enter the 8-digit code.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const resolved = await resolveLinkCode(codeInput);
      await proceed(resolved);
    } catch (e) {
      setError(errText(e.message));
      setBusy(false);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    if (passkey.length < MIN_PASSKEY_LENGTH) {
      showToast(`Passkey must be at least ${MIN_PASSKEY_LENGTH} characters`, 'error');
      return;
    }
    if (passkey !== confirmKey) {
      showToast('Passkeys do not match', 'error');
      return;
    }
    setPhase('saving');
    try {
      await provisionVaultFromMasterKey(user.uid, masterKeyRef.current, passkey);
      logActivity(user.uid, 'Device Linked', 'success', 'Smartphone', masterKeyRef.current);
      onUnlock(masterKeyRef.current);
    } catch (err) {
      showToast('Failed to save: ' + err.message, 'error');
      setPhase('received');
    }
  };

  return (
    <div className="min-h-[100dvh] w-full flex flex-col bg-paper text-ink">
      <header className="flex items-center gap-2 px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <button
          onClick={onCancel}
          className="flex items-center gap-1.5 text-[13px] text-muted hover:text-ink transition-colors"
        >
          <ArrowLeft size={15} /> Back
        </button>
      </header>

      <main className="flex-1 flex flex-col justify-center max-w-[26rem] w-full mx-auto px-6 animate-rise">
        {phase === 'verify' ? (
          <>
            <div className="w-12 h-12 rounded-2xl bg-accent-soft flex items-center justify-center mb-6">
              <ShieldCheck size={22} className="text-success" strokeWidth={2} />
            </div>
            <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight mb-2">
              Confirm it's you
            </h1>
            <p className="text-[15px] text-muted leading-relaxed mb-6">
              This code should match the one on your other device. There, tap{' '}
              <strong className="text-ink font-medium">Approve</strong> to finish — if the codes
              differ, cancel on both.
            </p>
            <div className="font-mono tabular text-4xl tracking-[0.2em] text-ink mb-8">{sas}</div>
            <p className="text-center text-[12px] text-faint flex items-center justify-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-fill animate-pulse" /> Waiting for
              the other device to approve…
            </p>
          </>
        ) : phase === 'received' || phase === 'saving' ? (
          <>
            <div className="w-12 h-12 rounded-2xl bg-accent-soft flex items-center justify-center mb-6">
              <ShieldCheck size={22} className="text-success" strokeWidth={2} />
            </div>
            <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight mb-2">
              Identity received
            </h1>
            <p className="text-[15px] text-muted leading-relaxed mb-9">
              Set a passkey to lock kunji on this device.
            </p>
            <form onSubmit={handleSave} className="space-y-4">
              <PasswordField
                label="Choose a passkey"
                autoFocus
                value={passkey}
                onChange={(e) => setPasskey(e.target.value)}
                className="text-lg"
              />
              <PasswordField
                label="Confirm passkey"
                value={confirmKey}
                onChange={(e) => setConfirmKey(e.target.value)}
                className="text-lg"
              />
              <div className="pt-5">
                <Btn type="submit" disabled={phase === 'saving'} className="w-full">
                  {phase === 'saving' ? (
                    <>
                      <Spinner /> Saving…
                    </>
                  ) : (
                    'Unlock on this device'
                  )}
                </Btn>
              </div>
            </form>
          </>
        ) : (
          <>
            <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight mb-2">
              Link this device
            </h1>
            <p className="text-[15px] text-muted leading-relaxed mb-7">
              On a device where kunji is already unlocked, open{' '}
              <strong className="text-ink font-medium">Security → Link a device</strong>, then enter
              the code it shows (or scan its QR).
            </p>
            <input
              autoFocus
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={8}
              value={codeInput}
              onChange={(e) => {
                setCodeInput(e.target.value.replace(/\D/g, '').slice(0, 8));
                if (error) setError('');
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') submitCode();
              }}
              placeholder="00000000"
              className="w-full bg-transparent border-0 border-b border-line rounded-none py-3 text-center text-4xl font-mono tabular tracking-[0.2em] text-ink placeholder:text-faint outline-none focus:border-accent transition-colors"
            />
            {error && <p className="text-danger text-[13px] mt-3">{error}</p>}
            <div className="pt-6">
              <Btn onClick={submitCode} disabled={busy || codeInput.length !== 8} className="w-full">
                {busy ? (
                  <>
                    <Spinner /> Linking…
                  </>
                ) : (
                  'Continue'
                )}
              </Btn>
            </div>
            <button
              onClick={() => {
                setError('');
                setShowScanner(true);
              }}
              className="mt-3 w-full flex items-center justify-center gap-1.5 text-sm font-medium text-muted hover:text-ink py-2 transition-colors"
            >
              <ScanLine size={15} /> Scan QR instead
            </button>
          </>
        )}
      </main>

      {showScanner && (
        <Suspense fallback={<div className="fixed inset-0 z-[200] bg-black" />}>
          <QRScannerOverlay onScan={handleScan} onClose={() => setShowScanner(false)} />
        </Suspense>
      )}
    </div>
  );
};

export default LinkDeviceScreen;
