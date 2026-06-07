import React, { useState, useEffect } from 'react';
import { Activity } from 'lucide-react';
import Sheet from './ui/Sheet';
import { listenToActivityLog } from '../services/activityLog';
import { activityIcon, TYPE_COLOR, relTime } from '../lib/activityFormat';

// Recent security activity for this device (sign-ins, approvals, failures). The Firestore
// listener lives here so it only runs while the sheet is open. Mirrors the sheet pattern.
const ActivitySheet = ({ userId, cryptoKey, onClose }) => {
  const [events, setEvents] = useState([]);
  useEffect(() => listenToActivityLog(userId, setEvents, 30, cryptoKey), [userId, cryptoKey]);

  return (
    <Sheet onClose={onClose} z={60} labelledBy="activity-title">
      <div className="flex items-center gap-2.5 mb-3">
        <Activity size={18} className="text-accent" />
        <h2 id="activity-title" className="text-lg font-semibold tracking-tight">
          Recent activity
        </h2>
      </div>
      <p className="text-[14px] text-muted leading-relaxed mb-5">
        Sign-ins, approvals, and security events recorded on this device.
      </p>
      {events.length === 0 ? (
        <p className="text-[13px] text-faint">No activity on this device yet.</p>
      ) : (
        <div className="divide-y divide-line border-t border-line max-h-[60vh] overflow-y-auto">
          {events.map((e) => {
            const Icon = activityIcon(e.icon);
            return (
              <div key={e.id} className="flex items-center gap-3 py-3">
                <Icon size={14} className={`${TYPE_COLOR[e.type] || 'text-muted'} shrink-0`} />
                <span className="text-[13px] text-ink flex-1 truncate">{e.action}</span>
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
