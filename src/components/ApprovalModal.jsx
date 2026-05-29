import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldX, Globe, Clock, Link, Fingerprint, Sparkles } from 'lucide-react';

const ApprovalModal = ({ session, onApprove, onDeny, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const sub = session?.sub || '';

  useEffect(() => {
    if (!session?.expiresAt) return;
    const tick = () => {
      const left = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
      setSecondsLeft(left);
      if (left === 0) onClose();
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [session?.expiresAt, onClose]);

  const handleApprove = async () => {
    setLoading(true);
    try { await onApprove(); } finally { setLoading(false); }
  };

  const handleDeny = async () => {
    setLoading(true);
    try { await onDeny(); } finally { setLoading(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#18181b] border border-[#27272a] rounded-3xl w-full max-w-sm p-6">
        <h2 className="text-lg font-bold text-white mb-4 text-center">Auth Request</h2>

        <div className="flex flex-col items-center gap-4">
          {session?.iconUrl ? (
            <img src={session.iconUrl} alt={session.appName} className="w-16 h-16 rounded-2xl object-cover" />
          ) : (
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center">
              <Link size={28} className="text-white" />
            </div>
          )}

          <div className="text-center">
            <p className="font-bold text-white text-lg">{session?.appName || 'Unknown App'}</p>
            <div className="flex items-center justify-center gap-1 text-sm text-gray-400 mt-1">
              <Globe size={13} />
              <span>{session?.domain}</span>
            </div>
            <p className="text-gray-500 text-sm mt-2">wants to verify your identity</p>
          </div>

          {sub && (
            <div className="flex items-center gap-2 bg-[#27272a]/50 border border-[#27272a] rounded-xl px-3 py-2 w-full">
              <Fingerprint size={14} className="text-amber-400 flex-shrink-0" />
              <p className="text-xs text-gray-400">
                Shared as <code className="text-gray-200 font-mono">{sub.slice(0, 4)}…{sub.slice(-4)}</code>
                <span className="text-gray-600"> · unique to this app</span>
              </p>
            </div>
          )}

          {session?.isNew && (
            <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-800/50 rounded-xl p-3 w-full">
              <Sparkles size={14} className="text-amber-400 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-amber-300">
                First time here — kunji will create a new identity for <strong>{session.audience}</strong>. Other apps can't see it.
              </p>
            </div>
          )}

          <div className="flex items-center gap-1.5 text-xs text-gray-500">
            <Clock size={12} />
            <span>Expires in {secondsLeft}s</span>
          </div>

          <div className="flex gap-3 w-full">
            <button onClick={handleDeny} disabled={loading}
              className="flex-1 flex items-center justify-center gap-2 py-3.5 rounded-xl bg-red-950/60 hover:bg-red-900/60 border border-red-800 text-red-300 font-semibold transition-colors disabled:opacity-50">
              <ShieldX size={16} /> Deny
            </button>
            <button onClick={handleApprove} disabled={loading || secondsLeft === 0}
              className="flex-1 flex items-center justify-center gap-2 py-3.5 rounded-xl bg-green-900/60 hover:bg-green-800/60 border border-green-700 text-green-300 font-semibold transition-colors disabled:opacity-50">
              <ShieldCheck size={16} /> {loading ? 'Signing in…' : 'Approve'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApprovalModal;
