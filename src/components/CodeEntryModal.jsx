import React, { useState } from 'react';
import Sheet from './ui/Sheet';
import { Btn } from './ui/primitives';

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
    <Sheet onClose={onClose} labelledBy="code-title">
      <h2 id="code-title" className="text-lg font-semibold tracking-tight mb-1">Enter login code</h2>
      <p className="text-[14px] text-muted mb-7">
        Type the 6-digit code shown on <span className="font-mono text-ink">{app.domain}</span>.
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
        className="w-full bg-transparent border-0 border-b border-line rounded-none py-3 text-center text-4xl font-mono tracking-[0.3em] text-ink placeholder:text-faint outline-none focus:border-accent transition-colors"
      />
      {error && <p className="text-danger text-[13px] mt-3">{error}</p>}

      <div className="flex items-center justify-end gap-1 mt-7">
        <Btn variant="quiet" onClick={onClose} disabled={busy}>Cancel</Btn>
        <Btn variant="primary" onClick={submit} disabled={busy || code.length !== 6}>
          {busy ? 'Checking…' : 'Continue'}
        </Btn>
      </div>
    </Sheet>
  );
};

export default CodeEntryModal;
