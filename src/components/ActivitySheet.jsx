import React, { useState, useEffect } from 'react';
import { Activity } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Monogram } from './ui/primitives';
import { listenToActivityLog } from '../services/activityLog';
import { activityIcon, TYPE_COLOR, relTime } from '../lib/activityFormat';
import { normalizeDomain } from '../lib/crypto/helpers';

// Recent activity. Global by default (all events on this identity); pass `domain` to scope it to a
// single app (same dialog, reused from AppDetailsModal). The Firestore listener lives here so it
// only runs while the sheet is open. Mirrors the sheet pattern.
const ActivitySheet = ({ userId, cryptoKey, onClose, domain, appName }) => {
  const [events, setEvents] = useState([]);
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
            return (
              <div key={e.id} className="flex items-center gap-3 py-3">
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
                </div>
                <span className="text-[11px] font-mono text-faint shrink-0 tabular">
                  {relTime(e.createdAt)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </Sheet>
  );
};

export default ActivitySheet;
