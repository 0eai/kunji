import React, { useState, useEffect } from 'react';
import { X, Copy, CheckCircle2, AlertTriangle, Hash, Fingerprint } from 'lucide-react';
import QRCode from 'qrcode';
import { deriveSubFromPublicKey } from '../services/identity';

const AppDetailsModal = ({ app, onClose }) => {
  const [copied, setCopied] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedSub, setCopiedSub] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [sub, setSub] = useState('');

  useEffect(() => {
    if (!app?.publicKey) return;
    const qrPayload = JSON.stringify({ kunjiApp: app.name, registeredAppId: app.id, publicKey: app.publicKey });
    QRCode.toDataURL(qrPayload, { width: 220, margin: 1, color: { dark: '#1e1b4b', light: '#ffffff' } })
      .then(setQrDataUrl)
      .catch(() => setQrDataUrl(''));
  }, [app]);

  useEffect(() => {
    if (!app?.publicKey) return;
    deriveSubFromPublicKey(app.publicKey).then(setSub).catch(() => setSub(''));
  }, [app?.publicKey]);

  const copyKey = () => { navigator.clipboard.writeText(app.publicKey); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  const copyId = () => { navigator.clipboard.writeText(app.id); setCopiedId(true); setTimeout(() => setCopiedId(false), 2000); };
  const copySub = () => { navigator.clipboard.writeText(sub); setCopiedSub(true); setTimeout(() => setCopiedSub(false), 2000); };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#18181b] border border-[#27272a] rounded-3xl w-full max-w-sm p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-white">{app?.name}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-[#27272a] transition-colors">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-4">
          {/* App ID */}
          <div>
            <p className="text-xs font-medium text-gray-500 mb-1 flex items-center gap-1">
              <Hash size={12} /> App ID <span className="text-gray-600">(VITE_REGISTERED_APP_ID)</span>
            </p>
            <div className="relative flex items-center">
              <code className="w-full p-2.5 pr-10 text-xs font-mono bg-black border border-[#27272a] rounded-xl text-gray-300 truncate block">
                {app?.id}
              </code>
              <button onClick={copyId} className="absolute right-2 p-1.5 rounded-lg hover:bg-[#27272a] transition-colors" title="Copy ID">
                {copiedId ? <CheckCircle2 size={14} className="text-green-400" /> : <Copy size={14} className="text-gray-500" />}
              </button>
            </div>
          </div>

          {/* QR Code */}
          {qrDataUrl && (
            <div className="bg-white rounded-2xl p-3 flex flex-col items-center">
              <p className="text-xs text-gray-500 mb-2">Scan to import public key</p>
              <img src={qrDataUrl} alt="Public key QR" className="w-[180px] h-[180px]" />
            </div>
          )}

          {/* Public Key */}
          <div>
            <p className="text-xs font-medium text-gray-500 mb-1">Ed25519 Public Key</p>
            <div className="relative">
              <textarea readOnly value={app?.publicKey || ''} rows={4}
                className="w-full p-2.5 text-xs font-mono bg-black border border-[#27272a] rounded-xl resize-none text-gray-300" />
              <button onClick={copyKey} className="absolute top-2 right-2 p-1.5 rounded-lg hover:bg-[#27272a] transition-colors" title="Copy key">
                {copied ? <CheckCircle2 size={14} className="text-green-400" /> : <Copy size={14} className="text-gray-500" />}
              </button>
            </div>
          </div>

          {/* Per-app subject ID */}
          {sub && (
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1 flex items-center gap-1">
                <Fingerprint size={12} /> Your ID for this app <span className="text-gray-600">(signedPayload.sub)</span>
              </p>
              <div className="relative">
                <code className="w-full p-2.5 pr-10 text-xs font-mono bg-black border border-[#27272a] rounded-xl text-gray-300 break-all block">
                  {sub}
                </code>
                <button onClick={copySub} className="absolute top-2 right-2 p-1.5 rounded-lg hover:bg-[#27272a] transition-colors" title="Copy ID">
                  {copiedSub ? <CheckCircle2 size={14} className="text-green-400" /> : <Copy size={14} className="text-gray-500" />}
                </button>
              </div>
              <p className="text-[11px] text-gray-600 mt-1.5 leading-relaxed">
                This is the stable identifier your app receives for you. It's unique to this app — other apps see a different ID, so they can't link your accounts.
              </p>
            </div>
          )}

          <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-800/50 rounded-xl p-3">
            <AlertTriangle size={14} className="text-amber-400 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-amber-300">
              Configure this public key in your app to verify signed auth tokens. The private key is stored securely in your vault.
            </p>
          </div>

          <button onClick={onClose} className="w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors">
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

export default AppDetailsModal;
