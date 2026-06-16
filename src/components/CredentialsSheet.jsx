import React, { useState, useEffect, useCallback } from 'react';
import { BadgeCheck, DownloadCloud } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, SheetHeading } from './ui/primitives';
import { listCredentials, groupByPool } from '../services/credentials';
import CredentialRow from './CredentialRow';
import CredentialDetailSheet from './CredentialDetailSheet';
import ReceiveCredentialSheet from './ReceiveCredentialSheet';

// Verified credentials the user holds (issued by trusted issuers, stored encrypted, shared across linked
// devices). This sheet is the LIST + a single "Receive a credential" action; per-credential details
// (issuer, proves, format, copies, remove) live in CredentialDetailSheet, and the two receive methods in
// ReceiveCredentialSheet. Presenting happens at login (ApprovalModal). Mirrors the apps/agents pattern.
const CredentialsSheet = ({ masterKey, onClose }) => {
  const [creds, setCreds] = useState(null); // null = loading
  const [detail, setDetail] = useState(null); // group open in the detail sheet
  const [showReceive, setShowReceive] = useState(false);

  const refresh = useCallback(() => {
    listCredentials(masterKey)
      .then(setCreds)
      .catch(() => setCreds([]));
  }, [masterKey]);
  useEffect(() => refresh(), [refresh]);

  const pools = creds === null ? null : groupByPool(creds);

  return (
    <Sheet onClose={onClose} z={60} labelledBy="creds-title">
      <SheetHeading
        id="creds-title"
        icon={BadgeCheck}
        info="Credentials issued to you by trusted issuers. When an app asks you to prove something (like being over 18), you present one — revealing only what's asked, never your date of birth. Each proof spends a fresh single-use copy, so verifiers can't link your visits to each other."
      >
        Verified credentials
      </SheetHeading>

      {pools === null ? (
        <p className="text-[13px] text-faint mb-5">Loading…</p>
      ) : pools.length === 0 ? (
        <p className="text-[15px] text-muted leading-relaxed mb-5">
          No credentials yet. Receive one from an issuer to prove a fact (like being over 18) without
          revealing your date of birth.
        </p>
      ) : (
        <div className="divide-y divide-line mb-5">
          {pools.map((g) => (
            <CredentialRow key={g.key} group={g} onOpen={() => setDetail(g)} />
          ))}
        </div>
      )}

      <Btn variant="primary" onClick={() => setShowReceive(true)} className="w-full">
        <DownloadCloud size={16} /> Receive a credential
      </Btn>

      {detail && (
        <CredentialDetailSheet
          group={detail}
          masterKey={masterKey}
          onClose={() => setDetail(null)}
          onChanged={refresh}
          onRemoved={(g) => {
            const gone = new Set(g.copies.map((c) => c.credId));
            setCreds((list) => (list || []).filter((x) => !gone.has(x.credId)));
            setDetail(null);
          }}
        />
      )}

      {showReceive && (
        <ReceiveCredentialSheet
          masterKey={masterKey}
          onClose={() => setShowReceive(false)}
          onReceived={refresh}
        />
      )}
    </Sheet>
  );
};

export default CredentialsSheet;
