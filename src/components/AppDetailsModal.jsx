import React, { useState, useEffect, useMemo } from 'react';
import { Copy, CheckCircle2, KeyRound, Trash2, Activity, ChevronRight, BadgeCheck } from 'lucide-react';
import { deriveSubFromPublicKey } from '../services/identity';
import { deriveHandle } from '../lib/kunjiHandle';
import Sheet from './ui/Sheet';
import ActivitySheet from './ActivitySheet';
import { SectionLabel, Monogram } from './ui/primitives';

const issuerHost = (iss) => {
  try {
    return new URL(iss).host;
  } catch {
    return iss;
  }
};

const AppDetailsModal = ({ app, userId, cryptoKey, profile, onClose, onEnterCode, onDelete }) => {
  // Whether this app currently sees the custom profile (set at approval; wallet-only metadata).
  const sharesProfile = !!(app?.sharedProfile && profile && (profile.displayName || profile.avatar));
  // Cumulative verified facts you've proven to this app (wallet-only metadata on the app record).
  const credentials = app?.shared?.credentials || [];
  const [sub, setSub] = useState('');
  const [copiedSub, setCopiedSub] = useState(false);
  const [showActivitySheet, setShowActivitySheet] = useState(false);

  useEffect(() => {
    if (!app?.publicKey) return;
    deriveSubFromPublicKey(app.publicKey)
      .then(setSub)
      .catch(() => setSub(''));
  }, [app?.publicKey]);

  // The default per-app identity (deterministic from sub) — what the app sees unless you share a profile.
  const handle = useMemo(() => (sub ? deriveHandle(sub) : null), [sub]);

  const copySub = () => {
    navigator.clipboard.writeText(sub);
    setCopiedSub(true);
    setTimeout(() => setCopiedSub(false), 2000);
  };

  return (
    <Sheet onClose={onClose} labelledBy="details-title">
      {/* Header */}
      <div className="flex items-center gap-3.5 mb-7">
        <Monogram name={app?.name} seed={app?.domain} src={app?.iconUrl} size="lg" />
        <div className="min-w-0">
          <h2 id="details-title" className="text-lg font-semibold tracking-tight truncate">
            {app?.name}
          </h2>
          <p className="text-[13px] font-mono text-muted truncate">{app?.domain}</p>
        </div>
      </div>

      {/* Per-app subject ID */}
      {sub && (
        <div className="mb-7">
          <SectionLabel
            className="mb-2.5"
            info="The stable identifier this app sees for you — unique to it, so apps can't link your accounts."
          >
            Your ID for this app
          </SectionLabel>
          <div className="flex items-start gap-3 border-y border-line py-3.5">
            <code className="flex-1 text-[12px] font-mono text-ink break-all leading-relaxed tabular">
              {sub}
            </code>
            <button
              onClick={copySub}
              className="shrink-0 text-muted hover:text-ink transition-colors"
              title="Copy ID"
            >
              {copiedSub ? <CheckCircle2 size={15} className="text-success" /> : <Copy size={15} />}
            </button>
          </div>
        </div>
      )}

      {/* What this app sees — the identity (custom profile or default) + verified facts you've proven */}
      <div className="mb-7">
        <SectionLabel
          className="mb-2.5"
          info="What this app learns about you. The default name & icon are generated just for this app — no real name, photo, or email. A custom profile is self-asserted and unverified; the app keeps a copy, so turning sharing off only affects future sign-ins. Verified facts are proven per sign-in — the app keeps only what it stored."
        >
          What this app sees
        </SectionLabel>
        {sharesProfile ? (
          <div className="flex items-center gap-3 border-y border-line py-3.5">
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
              <span className="block text-[13px] font-medium text-ink">Your custom profile</span>
              <span className="block text-[12px] text-muted truncate">
                {profile.displayName || 'Your photo'}
              </span>
            </span>
          </div>
        ) : (
          handle && (
            <div className="flex items-center gap-3 border-y border-line py-3.5">
              <img
                src={handle.avatarDataUri}
                alt=""
                className="w-9 h-9 rounded-lg border border-line shrink-0"
              />
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] font-medium text-ink truncate">{handle.name}</span>
                <span className="block text-[12px] text-muted">
                  Default identity — generated just for this app
                </span>
              </span>
            </div>
          )
        )}

        {/* Verified facts you've proven (cumulative; selective disclosure — only these claims, never your DOB) */}
        {credentials.length > 0 && (
          <div className="mt-3">
            <p className="text-[12px] uppercase tracking-wide text-faint mb-2">
              Verified facts you've proven
            </p>
            <div className="divide-y divide-line border-y border-line">
              {credentials.map((c, i) => (
                <div key={`${c.vct}-${c.iss}-${i}`} className="flex items-center gap-3 py-3">
                  <BadgeCheck size={17} className="text-success shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block text-[13px] font-mono text-ink truncate">
                      {(c.claims || []).join(', ') || c.vct}
                    </span>
                    <span className="block text-[12px] text-faint truncate">from {issuerHost(c.iss)}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="divide-y divide-line border-t border-line">
        <button
          onClick={() => setShowActivitySheet(true)}
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-ink hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
        >
          <Activity size={17} strokeWidth={1.75} className="text-muted" />
          <span className="flex-1 text-[15px] font-medium">Recent activity</span>
          <ChevronRight size={16} strokeWidth={1.75} className="text-faint" />
        </button>
        <button
          onClick={onEnterCode}
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-accent hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
        >
          <KeyRound size={17} strokeWidth={1.75} />{' '}
          <span className="text-[15px] font-medium">Sign in with a code</span>
        </button>
        <button
          onClick={onDelete}
          className="w-[calc(100%_+_1.5rem)] flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-danger hover:bg-danger-soft active:opacity-80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30"
        >
          <Trash2 size={17} strokeWidth={1.75} />{' '}
          <span className="text-[15px] font-medium">Remove app</span>
        </button>
      </div>

      {showActivitySheet && (
        <ActivitySheet
          domain={app.domain}
          appName={app?.name}
          userId={userId}
          cryptoKey={cryptoKey}
          onClose={() => setShowActivitySheet(false)}
        />
      )}
    </Sheet>
  );
};

export default AppDetailsModal;
