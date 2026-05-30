import React, { useState, useEffect, useRef } from 'react';
import QRCode from 'qrcode';
import { ArrowLeft, ShieldCheck } from 'lucide-react';
import { startLink, listenForLinkedKey } from '../services/linking';
import { provisionVaultFromMasterKey } from '../services/vault';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';
import { Field, Btn } from './ui/primitives';

const MIN_PASSKEY_LENGTH = 8;

// Device B: receive the vault master key from an existing device by QR, then set a
// local passkey for this device. After this, both devices share the same identity.
const LinkDeviceScreen = ({ user, onUnlock, onCancel }) => {
  const { showToast } = useToast();
  const [phase, setPhase] = useState('init'); // init → waiting → received → saving
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [passkey, setPasskey] = useState('');
  const [confirmKey, setConfirmKey] = useState('');
  const masterKeyRef = useRef(null);
  const privKeyRef = useRef(null);
  const unsubRef = useRef(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { linkId, privateKey, qrData } = await startLink();
        if (!alive) return;
        privKeyRef.current = privateKey;
        setQrDataUrl(await QRCode.toDataURL(qrData, { width: 240, margin: 1, color: { dark: '#1a1a18', light: '#ffffff' } }));
        setPhase('waiting');
        unsubRef.current = listenForLinkedKey(
          linkId,
          privateKey,
          (masterKey) => {
            masterKeyRef.current = masterKey;
            setPhase('received');
            unsubRef.current?.();
          },
          () => showToast('Could not decrypt the linked key. Try again.', 'error'),
        );
      } catch (e) {
        showToast('Failed to start linking: ' + e.message, 'error');
        onCancel();
      }
    })();
    return () => { alive = false; unsubRef.current?.(); };
  }, [onCancel, showToast]);

  const handleSave = async (e) => {
    e.preventDefault();
    if (passkey.length < MIN_PASSKEY_LENGTH) { showToast(`Passkey must be at least ${MIN_PASSKEY_LENGTH} characters`, 'error'); return; }
    if (passkey !== confirmKey) { showToast('Passkeys do not match', 'error'); return; }
    setPhase('saving');
    try {
      await provisionVaultFromMasterKey(user.uid, masterKeyRef.current, passkey);
      logActivity(user.uid, 'Device Linked', 'success', 'Smartphone');
      onUnlock(masterKeyRef.current);
    } catch (err) {
      showToast('Failed to save: ' + err.message, 'error');
      setPhase('received');
    }
  };

  return (
    <div className="min-h-[100dvh] w-full flex flex-col bg-paper text-ink">
      <header className="flex items-center gap-2 px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <button onClick={onCancel} className="flex items-center gap-1.5 text-[13px] text-muted hover:text-ink transition-colors">
          <ArrowLeft size={15} /> Back
        </button>
      </header>

      <main className="flex-1 flex flex-col justify-center max-w-[26rem] w-full mx-auto px-6">
        {phase === 'received' || phase === 'saving' ? (
          <>
            <div className="w-12 h-12 rounded-2xl bg-accent-soft flex items-center justify-center mb-6">
              <ShieldCheck size={22} className="text-success" strokeWidth={2.25} />
            </div>
            <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight mb-2">Identity received</h1>
            <p className="text-[15px] text-muted leading-relaxed mb-9">Set a passkey to lock kunji on this device.</p>
            <form onSubmit={handleSave} className="space-y-1">
              <Field type="password" autoFocus value={passkey} onChange={e => setPasskey(e.target.value)}
                placeholder="Choose a passkey" className="text-lg" />
              <Field type="password" value={confirmKey} onChange={e => setConfirmKey(e.target.value)}
                placeholder="Confirm passkey" className="text-lg" />
              <div className="pt-7">
                <Btn type="submit" disabled={phase === 'saving'} className="w-full">
                  {phase === 'saving' ? 'Saving…' : 'Unlock on this device'}
                </Btn>
              </div>
            </form>
          </>
        ) : (
          <>
            <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight mb-2">Link this device</h1>
            <p className="text-[15px] text-muted leading-relaxed mb-8">
              On a device where kunji is already unlocked, open <strong className="text-ink font-medium">Security → Link a device</strong> and scan this code.
            </p>
            <div className="flex justify-center mb-6">
              <div className="rounded-2xl border border-line p-4 bg-surface min-h-[224px] flex items-center justify-center">
                {qrDataUrl
                  ? <img src={qrDataUrl} alt="Device link QR" className="w-[192px] h-[192px]" />
                  : <span className="text-muted text-sm">Preparing…</span>}
              </div>
            </div>
            <p className="text-center text-[12px] text-faint flex items-center justify-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-fill animate-pulse" /> Waiting for the other device…
            </p>
          </>
        )}
      </main>
    </div>
  );
};

export default LinkDeviceScreen;
