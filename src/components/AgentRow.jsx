import React from 'react';
import { ChevronRight } from 'lucide-react';
import { Monogram } from './ui/primitives';
import { scopeId } from '../lib/capability';
import { expiryLabel, expiryTone } from '../lib/agentFormat';

/* One authorized agent — a hairline list row (mirrors AppRow). The whole row opens the agent's detail
   sheet; per-agent actions (notifications, revoke) live inside it. Used in the Dashboard agents view and the agent detail
   agents view. */
const AgentRow = ({ agent, onOpen }) => (
  <button
    onClick={onOpen}
    className="w-[calc(100%_+_1.5rem)] flex items-center gap-4 py-4 px-3 -mx-3 rounded-xl text-left group transition-colors
      hover:bg-line/40 active:bg-line/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
  >
    <Monogram name={agent.audience} seed={agent.audience} />
    <div className="flex-1 min-w-0">
      <p className="text-[15px] font-medium text-ink truncate">{agent.audience}</p>
      <p className="text-[13px] text-muted truncate">
        {(agent.scope || []).map(scopeId).join(', ')} ·{' '}
        <span className={expiryTone(agent.exp)}>{expiryLabel(agent.exp)}</span>
      </p>
    </div>
    <ChevronRight
      size={18}
      strokeWidth={1.75}
      className="text-faint group-hover:text-muted transition-colors shrink-0"
    />
  </button>
);

export default AgentRow;
