import React, { useState, useEffect, useMemo, useRef } from 'react';
import Sheet from './ui/Sheet';
import { Monogram, Btn } from './ui/primitives';
import { deriveHandle } from '../lib/kunjiHandle';

const ApprovalModal = ({ session, profile, onApprove, onDeny, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [shareProfile, setShareProfile] = useState(false); // Layer 2 consent — opt-in
  const sub = session?.sub || '';

  // Layer 1: the default pseudonymous identity the app will see (derived from sub).
  const handle = useMemo(() => (sub ? deriveHandle(sub) : null), [sub]);

  // Layer 2: only offer to share a custom profile when the RP asked AND one is set.
  const hasProfile = !!(profile && (profile.displayName || profile.avatar));
  const canShare = !!session?.requestProfile && hasProfile;

  // Seed the toggle's STARTING position from the profile's "share by default" preference, once the
  // profile has loaded (it may resolve after this modal mounts on a cold deep-link). This only sets
  // the initial value — the toggle itself is unchanged and the user can still turn it off.
  const seeded = useRef(false);
  useEffect(() => {
    if (!seeded.current && profile) {
      seeded.current = true;
      setShareProfile(canShare && !!profile.shareByDefault);
    }
  }, [profile, canShare]);

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
    try {
      await onApprove(canShare && shareProfile);
    } finally {
      setLoading(false);
    }
  };

  const handleDeny = async () => {
    setLoading(true);
    try {
      await onDeny();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Sheet onClose={onClose} labelledBy="approval-title">
      {/* Header — who is asking */}
      <div className="flex items-center gap-3.5 mb-7">
        <Monogram name={session?.appName} seed={session?.domain} src={session?.iconUrl} size="lg" />
        <div className="min-w-0">
          <h2 id="approval-title" className="text-lg font-semibold tracking-tight truncate">
            {session?.appName || 'Unknown app'}
          </h2>
          <p className="text-[13px] font-mono text-muted truncate">{session?.domain}</p>
        </div>
      </div>

      <p className="text-[15px] text-ink mb-6">
        Sign in to <span className="font-medium">{session?.appName || 'this app'}</span>?
      </p>

      {/* Detail rows */}
      <div className="divide-y divide-line border-y border-line mb-6">
        {handle && (
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">You'll appear as</span>
            <span className="flex items-center gap-2 min-w-0">
              <img
                src={handle.avatarDataUri}
                alt=""
                className="w-6 h-6 rounded-md border border-line shrink-0"
              />
              <span className="text-[13px] text-ink truncate">{handle.name}</span>
            </span>
          </div>
        )}
        {sub && (
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">Shared as</span>
            <span className="text-[13px] font-mono text-ink tabular">
              {sub.slice(0, 6)}…{sub.slice(-6)}
            </span>
          </div>
        )}
        {session?.isNew && (
          <div className="py-3.5">
            <p className="text-[13px] text-accent">
              First time here — kunji creates a new private identity for this app. Other apps can't
              see it.
            </p>
          </div>
        )}
        {!!session?.expiresAt && (
          <div className="flex items-center justify-between gap-4 py-3.5">
            <span className="text-[13px] text-muted">Expires in</span>
            <span className="text-[13px] font-mono text-ink tabular">{secondsLeft}s</span>
          </div>
        )}
      </div>

      {/* Layer 2 — optional custom profile sharing (only if the RP requested it) */}
      {canShare && (
        <button
          type="button"
          onClick={() => setShareProfile((v) => !v)}
          aria-pressed={shareProfile}
          className="w-full flex items-center gap-3 text-left mb-6 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
        >
          {profile.avatar ? (
            <img
              src={profile.avatar}
              alt=""
              className="w-9 h-9 rounded-lg border border-line shrink-0 object-cover"
            />
          ) : (
            <Monogram name={profile.displayName} size="sm" />
          )}
          <span className="min-w-0 flex-1">
            <span className="block text-[13px] font-medium text-ink">
              Share your profile with {session?.appName || 'this app'}
            </span>
            <span className="block text-[12px] text-muted truncate">
              {profile.displayName || 'Your photo'} — instead of the random name above
            </span>
          </span>
          <span
            className={`shrink-0 w-9 h-5 rounded-full p-0.5 transition-colors ${
              shareProfile ? 'bg-accent-fill' : 'bg-line'
            }`}
          >
            <span
              className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                shareProfile ? 'translate-x-4' : ''
              }`}
            />
          </span>
        </button>
      )}

      <p className="text-[12px] text-faint leading-relaxed mb-6">
        {canShare && shareProfile
          ? 'kunji will share your chosen name and photo with this app — and never your email or which other apps you use.'
          : 'kunji shares only this ID — never your email, real name, or which other apps you use. The name and icon above are generated just for this app.'}
      </p>

      <div className="flex items-center justify-end gap-1">
        <Btn variant="quiet" onClick={handleDeny} disabled={loading}>
          Deny
        </Btn>
        <Btn
          variant="primary"
          onClick={handleApprove}
          disabled={loading || (!!session?.expiresAt && secondsLeft === 0)}
        >
          {loading ? 'Signing in…' : 'Approve'}
        </Btn>
      </div>
    </Sheet>
  );
};

export default ApprovalModal;
