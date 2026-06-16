import React from 'react';
import { ChevronRight } from 'lucide-react';
import { Monogram } from './ui/primitives';

/* A single registered app — a hairline list row. The whole row opens details;
   per-app actions (sign-in code, remove) live inside the detail sheet. */
const AppRow = ({ app, onOpen }) => (
  <button
    onClick={onOpen}
    className="w-[calc(100%_+_1.5rem)] flex items-center gap-4 py-4 px-3 -mx-3 rounded-xl text-left group transition-colors
      hover:bg-line/40 active:bg-line/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
  >
    <Monogram name={app.name} seed={app.domain} src={app.iconUrl} />
    <div className="flex-1 min-w-0">
      <p className="text-[15px] font-medium text-ink truncate">{app.name}</p>
      <p className="text-[13px] font-mono text-muted truncate">{app.domain}</p>
    </div>
    <ChevronRight
      size={18}
      strokeWidth={1.75}
      className="text-faint group-hover:text-muted transition-colors shrink-0"
    />
  </button>
);

export default AppRow;
