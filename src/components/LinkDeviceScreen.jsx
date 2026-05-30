import React, { useState, useEffect, useRef } from 'react';
import QRCode from 'qrcode';
import { Smartphone, ArrowLeft, ShieldCheck } from 'lucide-react';
import { startLink, listenForLinkedKey } from '../services/linking';
import { provisionVaultFromMasterKey } from '../services/vault';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';

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
        setQrDataUrl(await QRCode.toDataURL(qrData, { width: 240, margin: 1, color: { dark: '#1c1606', light: '#fbbf24' } }));
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
    <div className="h-[100dvh] w-full flex flex-col items-center justify-center bg-[#f6f7f9] text-[#18181b] p-6">
      <div className="bg-white p-8 rounded-3xl shadow-2xl max-w-sm w-full border border-[#e6e8eb]">
        <button onClick={onCancel} className="text-xs text-gray-500 hover:text-[#18181b] flex items-center gap-1.5 mb-5 transition-colors">
          <ArrowLeft size={13} /> Back
        </button>

        {phase === 'received' || phase === 'saving' ? (
          <>
            <div className="mx-auto w-16 h-16 bg-green-100 rounded-2xl flex items-center justify-center mb-6">
              <ShieldCheck size={32} className="text-green-600" />
            </div>
            <h2 className="text-2xl font-bold mb-1 text-center tracking-tight">Identity received</h2>
            <p className="text-center mb-6 text-sm text-gray-600">Set a passkey to lock kunji on this device.</p>
            <form onSubmit={handleSave}>
              <input
                type="password" autoFocus value={passkey} onChange={e => setPasskey(e.target.value)}
                placeholder="Choose a passkey"
                className="w-full p-4 rounded-xl bg-[#f1f2f4] border border-[#e6e8eb] text-[#18181b] mb-2 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none placeholder-gray-400 font-medium tracking-wide"
              />
              <input
                type="password" value={confirmKey} onChange={e => setConfirmKey(e.target.value)}
                placeholder="Confirm passkey"
                className="w-full p-4 rounded-xl bg-[#f1f2f4] border border-[#e6e8eb] text-[#18181b] mb-3 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none placeholder-gray-400 font-medium tracking-wide"
              />
              <button type="submit" disabled={phase === 'saving'}
                className="w-full py-4 bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-black rounded-xl font-bold transition-all active:scale-[0.98]">
                {phase === 'saving' ? 'Saving…' : 'Unlock on this device'}
              </button>
            </form>
          </>
        ) : (
          <>
            <div className="mx-auto w-16 h-16 bg-amber-500 rounded-2xl flex items-center justify-center mb-6">
              <Smartphone size={32} className="text-black" />
            </div>
            <h2 className="text-2xl font-bold mb-1 text-center tracking-tight">Link this device</h2>
            <p className="text-center mb-6 text-sm text-gray-600">
              On a device where kunji is already unlocked, open <strong className="text-gray-900">Security → Scan device QR</strong> and scan this code.
            </p>
            <div className="bg-white rounded-2xl p-3 flex items-center justify-center mb-4 min-h-[200px]">
              {qrDataUrl
                ? <img src={qrDataUrl} alt="Device link QR" className="w-[200px] h-[200px]" />
                : <span className="text-gray-600 text-sm">Preparing…</span>}
            </div>
            <p className="text-center text-xs text-gray-400 flex items-center justify-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" /> Waiting for the other device…
            </p>
          </>
        )}
      </div>
    </div>
  );
};

export default LinkDeviceScreen;
