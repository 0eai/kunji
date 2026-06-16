import React from 'react';
import { ChevronRight } from 'lucide-react';
import { Monogram } from './ui/primitives';
import { claimNamesOf, isKunjiIssuer, issuerName } from '../lib/credentialFormat';

/* One held credential (a pool) — a hairline list row (mirrors AppRow/AgentRow). The whole row opens the
   credential's detail sheet; per-credential actions (receive more, remove) live inside it. `group` is a
   groupByPool entry: { key, vct, iss, brand, verifiedVia, oneTime, unlinkable, remaining, sample }. */
const CredentialRow = ({ group: g, onOpen }) => (
  <button
    onClick={onOpen}
    className="w-[calc(100%_+_1.5rem)] flex items-center gap-4 py-4 px-3 -mx-3 rounded-xl text-left group transition-colors
      hover:bg-line/40 active:bg-line/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
  >
    <Monogram name={issuerName(g)} seed={g.iss} src={isKunjiIssuer(g.iss) ? '/icons/icon.svg' : undefined} />
    <div className="flex-1 min-w-0">
      <p className="text-[15px] font-medium text-ink truncate">{g.vct}</p>
      <p className="text-[13px] text-muted truncate">
        {claimNamesOf(g.sample).join(', ')} · {issuerName(g)}
      </p>
      {g.unlinkable ? (
        <p className="text-[11px] text-accent mt-0.5">unlinkable · a fresh proof each time</p>
      ) : g.oneTime ? (
        <p className="text-[11px] text-faint mt-0.5">
          single-use · {g.remaining} {g.remaining === 1 ? 'copy' : 'copies'} left
        </p>
      ) : null}
    </div>
    <ChevronRight
      size={18}
      strokeWidth={1.75}
      className="text-faint group-hover:text-muted transition-colors shrink-0"
    />
  </button>
);

export default CredentialRow;
