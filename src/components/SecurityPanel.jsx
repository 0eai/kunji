import React, { useState, useEffect, useRef } from 'react';
import { X, KeyRound, Copy, CheckCircle2, AlertTriangle, Smartphone, ScanLine } from 'lucide-react';
import { exportRecoveryKey } from '../services/vault';
import { completeLink } from '../services/linking';
import QRScannerOverlay from './QRScannerOverlay';
import { useToast } from '../contexts/ToastContext';

const MIN_PASSPHRASE = 8;
const CLEAR_MS = 60000;

const SecurityPanel = ({ userId, cryptoKey, onClose }) => {
  const { showToast } = useToast();

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

        <div className="space-y-6">
          {/* Link a device */}
          <section>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-1">
              <Smartphone size={15} className="text-amber-400" /> Link a device
            </h3>
            <p className="text-xs text-gray-500 mb-3">
              Add another device to this identity. On the new device choose “Link from another device”, then scan its QR here.
            </p>
            <button
              onClick={() => setShowScanner(true)}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-semibold transition-colors"
            >
              <ScanLine size={16} /> Scan device QR
            </button>
          </section>

          <div className="border-t border-[#27272a]" />

          {/* Export recovery key */}
          <section>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-1">
              <KeyRound size={15} className="text-amber-400" /> Export recovery key
            </h3>
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
          </section>
        </div>
      </div>

      {showScanner && (
        <QRScannerOverlay onScan={handleLinkScan} onClose={() => setShowScanner(false)} />
      )}
    </div>
  );
};

export default SecurityPanel;
