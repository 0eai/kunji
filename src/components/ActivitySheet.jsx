import React, { useState, useEffect } from 'react';
import { Activity } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Monogram } from './ui/primitives';
import { listenToActivityLog } from '../services/activityLog';
import { activityIcon, TYPE_COLOR, relTime } from '../lib/activityFormat';
import { normalizeDomain } from '../lib/crypto/helpers';
import ActivityDetailSheet from './ActivityDetailSheet';

// A one-line "what was shared" hint for a sign-in event (the full breakdown is in ActivityDetailSheet).
const sharedHint = (s) => {
  if (!s) return '';
  const parts = [];
  if (s.profile) parts.push('shared profile');
  for (const c of s.credentials || []) parts.push(`proved ${(c.claims || []).join(', ') || c.vct}`);
  for (const sc of s.scopes || []) parts.push(sc);
  return parts.join(' · ');
};

// Recent activity. Global by default (all events on this identity); pass `domain` to scope it to a
// single app (same dialog, reused from AppDetailsModal). The Firestore listener lives here so it
// only runs while the sheet is open. Mirrors the sheet pattern.
const ActivitySheet = ({ userId, cryptoKey, onClose, domain, appName }) => {
  const [events, setEvents] = useState([]);
  const [detail, setDetail] = useState(null); // event opened in the detail sheet
  useEffect(() => {
    const want = domain ? normalizeDomain(domain) : null;
    return listenToActivityLog(
      userId,
      (all) => setEvents(want ? all.filter((e) => e.domain && normalizeDomain(e.domain) === want) : all),
      30,
      cryptoKey,
    );
  }, [userId, cryptoKey, domain]);

  return (
    <Sheet onClose={onClose} z={60} labelledBy="activity-title">
      <div className="flex items-center gap-2.5 mb-3">
        <Activity size={18} className="text-accent" />
        <h2 id="activity-title" className="text-lg font-semibold tracking-tight">
          Recent activity
        </h2>
      </div>
      <p className="text-[14px] text-muted leading-relaxed mb-5">
        {domain
          ? `Sign-ins and security events for ${appName || domain} on this identity.`
          : 'Sign-ins, approvals, and security events on this identity.'}
      </p>
      {events.length === 0 ? (
        <p className="text-[13px] text-faint">
          {domain ? 'No activity for this app yet.' : 'No activity on this identity yet.'}
        </p>
      ) : (
        <div className="divide-y divide-line border-t border-line max-h-[60vh] overflow-y-auto">
          {events.map((e) => {
            const Icon = activityIcon(e.icon);
            const hint = sharedHint(e.shared);
            return (
              <button
                key={e.id}
                onClick={() => setDetail(e)}
                className="w-full flex items-center gap-3 py-3 text-left hover:bg-line/30 active:bg-line/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded-lg"
              >
                {!domain && e.domain ? (
                  <Monogram name={e.domain} seed={e.domain} size="sm" />
                ) : (
                  <Icon size={14} className={`${TYPE_COLOR[e.type] || 'text-muted'} shrink-0`} />
                )}
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] text-ink truncate">{e.action}</p>
                  {(e.device || e.ip) && (
                    <p className="text-[11px] text-faint truncate">
                      {[e.device, e.ip].filter(Boolean).join(' · ')}
                    </p>
                  )}
                  {hint && <p className="text-[11px] text-accent truncate">{hint}</p>}
                </div>
                <span className="text-[11px] font-mono text-faint shrink-0 tabular">
                  {relTime(e.createdAt)}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {detail && <ActivityDetailSheet event={detail} onClose={() => setDetail(null)} />}
    </Sheet>
  );
};

export default ActivitySheet;
