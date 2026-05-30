import React from 'react';
import { ChevronRight } from 'lucide-react';
import { Monogram } from './ui/primitives';

/* A single registered app — a hairline list row. The whole row opens details;
   per-app actions (sign-in code, remove) live inside the detail sheet. */
const AppRow = ({ app, onOpen }) => (
  <button
    onClick={onOpen}
    className="w-full flex items-center gap-4 py-4 text-left group"
  >
    <Monogram name={app.name} src={app.iconUrl} />
    <div className="flex-1 min-w-0">
      <p className="text-[15px] font-medium text-ink truncate">{app.name}</p>
      <p className="text-[13px] font-mono text-muted truncate">{app.domain}</p>
    </div>
    <ChevronRight size={18} className="text-faint group-hover:text-muted transition-colors shrink-0" />
  </button>
);

export default AppRow;
