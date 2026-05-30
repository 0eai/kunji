import React, { useState } from 'react';
import { X, KeyRound } from 'lucide-react';

// Device-authorization: type the 6-digit code the app (already known to kunji) shows.
const CodeEntryModal = ({ app, onSubmit, onClose }) => {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!/^\d{6}$/.test(code)) { setError('Enter the 6-digit code.'); return; }
    setBusy(true);
    setError('');
    try {
      await onSubmit(app, code);
    } catch (e) {
      const m = e.message === 'invalid_code' ? 'That code is wrong or already used.'
        : e.message === 'expired_code' ? 'That code expired — get a fresh one.'
        : e.message === 'rate_limited' ? 'Too many attempts. Wait a minute.'
        : e.message === 'untrusted_callback' ? 'Untrusted login request.'
        : 'Could not sign in: ' + e.message;
      setError(m);
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-white border border-[#e6e8eb] rounded-3xl w-full max-w-sm p-6">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-bold text-[#18181b] flex items-center gap-2">
            <KeyRound size={16} className="text-amber-600" /> Enter login code
          </h2>
          <button onClick={onClose} className="p-1.5 rounded-lg text-gray-500 hover:text-[#18181b] hover:bg-[#eef0f2] transition-colors">
            <X size={18} />
          </button>
        </div>
        <p className="text-xs text-gray-500 mb-4">
          Type the 6-digit code shown on <strong className="text-gray-700">{app.domain}</strong>.
        </p>

        <input
          autoFocus
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={6}
          value={code}
          onChange={(e) => { setCode(e.target.value.replace(/\D/g, '').slice(0, 6)); if (error) setError(''); }}
          onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
          placeholder="000000"
          className="w-full p-4 rounded-xl bg-[#f1f2f4] border border-[#e6e8eb] text-[#18181b] text-center text-2xl font-mono tracking-[0.4em] placeholder-gray-400 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none"
        />
        {error && <p className="text-red-600 text-sm mt-2">{error}</p>}

        <div className="flex gap-2 mt-4">
          <button onClick={onClose} disabled={busy}
            className="flex-1 py-3 rounded-xl bg-[#eef0f2] hover:bg-[#e2e5e9] text-[#18181b] font-medium transition-colors">
            Cancel
          </button>
          <button onClick={submit} disabled={busy || code.length !== 6}
            className="flex-1 py-3 rounded-xl bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-black font-semibold transition-colors">
            {busy ? 'Checking…' : 'Continue'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default CodeEntryModal;
