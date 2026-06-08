import React from 'react';
import Sheet from './ui/Sheet';
import AppRow from './AppRow';
import { SectionLabel } from './ui/primitives';

/* Top-level "Enter a code" entry. A bare 6-digit code can't say which app it's for, so the user
   picks one of their existing apps first — that gives the wallet the domain to resolve the code
   against (https://{app.domain}/kunji/session?code=…). Selecting an app hands off to CodeEntryModal.
   Only apps already in the vault appear here; a brand-new app is added by scanning its QR. */
const CodePickerSheet = ({ apps, onPick, onClose }) => (
  <Sheet onClose={onClose} labelledBy="code-pick-title">
    <h2 id="code-pick-title" className="text-lg font-semibold tracking-tight mb-1">
      Sign in with a code
    </h2>
    <p className="text-[14px] text-muted leading-relaxed mb-6">
      Pick the app you're signing in to, then type the 6-digit code it's showing.
    </p>

    <SectionLabel count={apps.length} className="pb-1">
      Your apps
    </SectionLabel>
    <div className="divide-y divide-line">
      {apps.map((app) => (
        <AppRow key={app.id} app={app} onOpen={() => onPick(app)} />
      ))}
    </div>
  </Sheet>
);

export default CodePickerSheet;
