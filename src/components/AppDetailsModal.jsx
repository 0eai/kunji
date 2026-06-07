import React, { useState, useEffect } from 'react';
import { Copy, CheckCircle2, KeyRound, Trash2, ChevronRight } from 'lucide-react';
import { deriveSubFromPublicKey } from '../services/identity';
import { listenToActivityLog } from '../services/activityLog';
import { normalizeDomain } from '../lib/crypto/helpers';
import Sheet from './ui/Sheet';
import { SectionLabel, Monogram } from './ui/primitives';
import { activityIcon, TYPE_COLOR, relTime } from '../lib/activityFormat';

const AppDetailsModal = ({ app, userId, cryptoKey, onClose, onEnterCode, onDelete }) => {
  const [sub, setSub] = useState('');
  const [copiedSub, setCopiedSub] = useState(false);
  const [events, setEvents] = useState([]);
  const [showActivity, setShowActivity] = useState(false); // collapsed by default

  useEffect(() => {
    if (!app?.publicKey) return;
    deriveSubFromPublicKey(app.publicKey)
      .then(setSub)
      .catch(() => setSub(''));
  }, [app?.publicKey]);

  // This device's recent activity for this app (tagged with its domain). Compare
  // normalized both ways so casing/port/trailing-dot variants still match.
  useEffect(() => {
    if (!userId) return;
    const want = normalizeDomain(app.domain);
    const unsub = listenToActivityLog(
      userId,
      (all) => {
        setEvents(all.filter((e) => e.domain && normalizeDomain(e.domain) === want).slice(0, 8));
      },
      50,
      cryptoKey,
    );
    return unsub;
  }, [userId, cryptoKey, app.domain]);

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
          <SectionLabel className="mb-2.5">Your ID for this app</SectionLabel>
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
          <p className="text-[12px] text-faint mt-2 leading-relaxed">
            The stable identifier this app sees for you — unique to it, so apps can't link your
            accounts.
          </p>
        </div>
      )}

      {/* Recent activity — collapsed by default */}
      <div className="mb-7">
        <button
          onClick={() => setShowActivity((v) => !v)}
          aria-expanded={showActivity}
          className="w-full flex items-center justify-between gap-2 py-1 group focus-visible:outline-none"
        >
          <SectionLabel count={events.length || null}>Recent activity</SectionLabel>
          <ChevronRight
            size={16}
            strokeWidth={1.75}
            className={`text-faint group-hover:text-muted transition-transform ${showActivity ? 'rotate-90' : ''}`}
          />
        </button>
        {showActivity &&
          (events.length === 0 ? (
            <p className="text-[13px] text-faint py-2">
              No activity for this app on this device yet.
            </p>
          ) : (
            <div className="divide-y divide-line border-t border-line mt-2.5">
              {events.map((e) => {
                const Icon = activityIcon(e.icon);
                return (
                  <div key={e.id} className="flex items-center gap-3 py-3">
                    <Icon size={14} className={`${TYPE_COLOR[e.type] || 'text-muted'} shrink-0`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[13px] text-ink truncate">{e.action}</p>
                      {(e.device || e.ip) && (
                        <p className="text-[11px] text-faint truncate">
                          {[e.device, e.ip].filter(Boolean).join(' · ')}
                        </p>
                      )}
                    </div>
                    <span className="text-[11px] font-mono text-faint shrink-0 tabular">
                      {relTime(e.createdAt)}
                    </span>
                  </div>
                );
              })}
            </div>
          ))}
      </div>

      {/* Actions */}
      <div className="divide-y divide-line border-t border-line">
        <button
          onClick={onEnterCode}
          className="w-full flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-accent hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
        >
          <KeyRound size={17} strokeWidth={1.75} />{' '}
          <span className="text-[15px] font-medium">Sign in with a code</span>
        </button>
        <button
          onClick={onDelete}
          className="w-full flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-danger hover:bg-danger-soft active:opacity-80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger/30"
        >
          <Trash2 size={17} strokeWidth={1.75} />{' '}
          <span className="text-[15px] font-medium">Remove app</span>
        </button>
      </div>
    </Sheet>
  );
};

export default AppDetailsModal;
