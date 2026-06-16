import React from 'react';
import { BadgeCheck, ShieldCheck, UserCircle } from 'lucide-react';
import Sheet from './ui/Sheet';
import { SectionLabel } from './ui/primitives';
import { activityIcon, TYPE_COLOR } from '../lib/activityFormat';

// Per-event detail for one Recent-activity entry (opened from ActivitySheet). Read-only. For a sign-in
// it breaks down exactly what that session shared — identity (default vs custom profile), verified facts
// proven, and any action scopes. Scopes live HERE (per-session, precise), not as a standing per-app list.
const fmtWhen = (ts) => {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return '';
  }
};

const MetaRow = ({ label, children }) => (
  <div className="flex items-start justify-between gap-4 py-3">
    <span className="text-[13px] text-muted shrink-0">{label}</span>
    <span className="text-[13px] text-ink text-right break-all min-w-0">{children}</span>
  </div>
);

const SharedRow = ({ icon: Icon, iconClass = 'text-muted', title, sub, mono = false }) => (
  <div className="flex items-center gap-3 py-3">
    <Icon size={17} strokeWidth={1.75} className={`${iconClass} shrink-0`} />
    <span className="min-w-0 flex-1">
      <span className={`block text-[13px] text-ink truncate ${mono ? 'font-mono' : ''}`}>{title}</span>
      {sub && <span className="block text-[12px] text-faint truncate">{sub}</span>}
    </span>
  </div>
);

const ActivityDetailSheet = ({ event, onClose }) => {
  const e = event || {};
  const Icon = activityIcon(e.icon);
  const shared = e.shared || null;
  const creds = shared?.credentials || [];
  const scopes = shared?.scopes || [];
  return (
    <Sheet onClose={onClose} z={70} labelledBy="actdetail-title">
      <div className="flex items-center gap-2.5 mb-5">
        <Icon size={18} className={TYPE_COLOR[e.type] || 'text-accent'} />
        <h2 id="actdetail-title" className="text-lg font-semibold tracking-tight">
          {e.action || 'Activity'}
        </h2>
      </div>

      <div className="divide-y divide-line border-y border-line mb-7">
        {e.createdAt != null && <MetaRow label="When">{fmtWhen(e.createdAt)}</MetaRow>}
        {e.device && <MetaRow label="Device">{e.device}</MetaRow>}
        {e.ip && <MetaRow label="IP">{e.ip}</MetaRow>}
        {e.domain && <MetaRow label="App">{e.domain}</MetaRow>}
      </div>

      {shared && (
        <div className="mb-2">
          <SectionLabel className="mb-2.5">What you shared this sign-in</SectionLabel>
          <div className="divide-y divide-line border-y border-line">
            <SharedRow
              icon={UserCircle}
              title={shared.profile ? 'Your custom profile' : 'Default identity'}
              sub={
                shared.profile
                  ? 'A self-asserted name / photo you chose to share'
                  : 'A random name & icon unique to this app — no real name, photo, or email'
              }
            />
            {creds.map((c, i) => (
              <SharedRow
                key={`c-${i}`}
                icon={BadgeCheck}
                iconClass="text-success"
                title={(c.claims || []).join(', ') || c.vct}
                sub="Verified fact — selective disclosure, never your date of birth"
                mono
              />
            ))}
            {scopes.map((s, i) => (
              <SharedRow key={`s-${i}`} icon={ShieldCheck} title={s} sub="Permission granted" mono />
            ))}
          </div>
        </div>
      )}
    </Sheet>
  );
};

export default ActivityDetailSheet;
