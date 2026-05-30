import React, { useState, useEffect } from 'react';
import Sheet from './ui/Sheet';
import { Monogram, Btn } from './ui/primitives';

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
    <Sheet onClose={onClose} labelledBy="approval-title">
      {/* Header — who is asking */}
      <div className="flex items-center gap-3.5 mb-7">
        <Monogram name={session?.appName} src={session?.iconUrl} size="lg" />
        <div className="min-w-0">
          <h2 id="approval-title" className="text-lg font-semibold tracking-tight truncate">{session?.appName || 'Unknown app'}</h2>
          <p className="text-[13px] font-mono text-muted truncate">{session?.domain}</p>
        </div>
      </div>

      <p className="text-[15px] text-ink mb-6">
        Sign in to <span className="font-medium">{session?.appName || 'this app'}</span>?
      </p>

      {/* Detail rows */}
      <div className="divide-y divide-line border-y border-line mb-6">
        {sub && (
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">Shared as</span>
            <span className="text-[13px] font-mono text-ink">{sub.slice(0, 6)}…{sub.slice(-6)}</span>
          </div>
        )}
        {session?.isNew && (
          <div className="py-3.5">
            <p className="text-[13px] text-accent">
              First time here — kunji creates a new private identity for this app. Other apps can't see it.
            </p>
          </div>
        )}
        {!!session?.expiresAt && (
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">Expires in</span>
            <span className="text-[13px] font-mono text-ink">{secondsLeft}s</span>
          </div>
        )}
      </div>

      <div className="flex items-center justify-end gap-1">
        <Btn variant="quiet" onClick={handleDeny} disabled={loading}>Deny</Btn>
        <Btn variant="primary" onClick={handleApprove} disabled={loading || (!!session?.expiresAt && secondsLeft === 0)}>
          {loading ? 'Signing in…' : 'Approve'}
        </Btn>
      </div>
    </Sheet>
  );
};

export default ApprovalModal;
