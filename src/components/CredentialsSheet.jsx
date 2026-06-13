import React, { useState, useEffect, useCallback } from 'react';
import { BadgeCheck, Trash2, DownloadCloud } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, Field, Monogram } from './ui/primitives';
import { listCredentials, deleteCredential, receiveFromIssuer } from '../services/credentials';
import { parseSdJwt } from '../lib/vc';
import { useToast } from '../contexts/ToastContext';

const claimNames = (sdjwt) => {
  try {
    return parseSdJwt(sdjwt).disclosures.map((d) => d.name);
  } catch {
    return [];
  }
};
const issuerLabel = (iss) => {
  try {
    return new URL(iss).host;
  } catch {
    return iss;
  }
};

// Verified credentials the user holds (issued by trusted issuers, stored encrypted, shared across
// linked devices). Receive one from an issuer, see what you hold, remove any. Presenting them happens
// at login (ApprovalModal). Mirrors the AgentsSheet pattern.
const CredentialsSheet = ({ masterKey, onClose }) => {
  const { showToast } = useToast();
  const [creds, setCreds] = useState(null); // null = loading
  const [issuerUrl, setIssuerUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [deleting, setDeleting] = useState('');

  const refresh = useCallback(() => {
    listCredentials(masterKey)
      .then(setCreds)
      .catch(() => setCreds([]));
  }, [masterKey]);
  useEffect(() => refresh(), [refresh]);

  const receive = async () => {
    setBusy(true);
    try {
      await receiveFromIssuer(masterKey, issuerUrl);
      showToast('Credential received.');
      setIssuerUrl('');
      refresh();
    } catch (e) {
      showToast(e.message || 'Could not receive a credential.', 'error');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (c) => {
    setDeleting(c.credId);
    try {
      await deleteCredential(masterKey, c.credId);
      showToast('Credential removed.');
      setCreds((list) => (list || []).filter((x) => x.credId !== c.credId));
      return true;
    } catch (e) {
      showToast('Could not remove: ' + (e.message || e), 'error');
      return false;
    } finally {
      setDeleting('');
    }
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="creds-title">
      <div className="flex items-center gap-2.5 mb-3">
        <BadgeCheck size={18} className="text-accent" />
        <h2 id="creds-title" className="text-lg font-semibold tracking-tight">
          Verified credentials
        </h2>
      </div>
      <p className="text-[14px] text-muted leading-relaxed mb-5">
        Credentials issued to you by trusted issuers. When an app asks you to prove something (like
        being over 18), you present one — revealing only what's asked, never your date of birth.
      </p>

      {creds === null ? (
        <p className="text-[13px] text-faint mb-5">Loading…</p>
      ) : creds.length === 0 ? (
        <p className="text-[13px] text-faint mb-5">No credentials yet.</p>
      ) : (
        <div className="divide-y divide-line border-y border-line mb-5">
          {creds.map((c) => (
            <div key={c.credId} className="flex items-center gap-3 py-3">
              <Monogram name={issuerLabel(c.iss)} seed={c.iss} size="sm" />
              <div className="flex-1 min-w-0">
                <p className="text-[14px] text-ink truncate">{c.vct}</p>
                <p className="text-[11px] text-faint truncate">
                  {claimNames(c.sdjwt).join(', ')} · from {issuerLabel(c.iss)}
                </p>
              </div>
              <button
                onClick={() => setConfirm(c)}
                className="shrink-0 inline-flex items-center gap-1 text-[13px] font-medium text-danger hover:opacity-80 transition-opacity"
                title="Remove"
              >
                <Trash2 size={15} />
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="text-[12px] uppercase tracking-wide text-faint mb-2">Receive from an issuer</div>
      <Field label="Issuer URL (https://…)" value={issuerUrl} onChange={(e) => setIssuerUrl(e.target.value)} />
      <Btn variant="primary" onClick={receive} disabled={busy || !issuerUrl.trim()} className="w-full mt-3">
        <DownloadCloud size={16} /> {busy ? 'Receiving…' : 'Receive credential'}
      </Btn>

      {confirm && (
        <Sheet onClose={() => !deleting && setConfirm(null)} z={70} labelledBy="del-cred-title">
          <div className="flex items-center gap-2.5 mb-3">
            <Trash2 size={18} className="text-danger" />
            <h2 id="del-cred-title" className="text-lg font-semibold tracking-tight">
              Remove this credential?
            </h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            You'll no longer be able to present <span className="font-mono text-ink">{confirm.vct}</span> from{' '}
            {issuerLabel(confirm.iss)}. You can receive it again from the issuer.
          </p>
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setConfirm(null)} disabled={!!deleting}>
              Cancel
            </Btn>
            <Btn
              variant="danger"
              onClick={async () => {
                if (await remove(confirm)) setConfirm(null);
              }}
              disabled={!!deleting}
            >
              {deleting ? 'Removing…' : 'Remove'}
            </Btn>
          </div>
        </Sheet>
      )}
    </Sheet>
  );
};

export default CredentialsSheet;
