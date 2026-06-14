import React, { useState } from 'react';
import { BadgeCheck, CheckCircle2, Circle } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn } from './ui/primitives';
import { presentViaOid4vp } from '../services/credentials';
import { useToast } from '../contexts/ToastContext';

const issuerHost = (iss) => {
  try {
    return new URL(iss).host;
  } catch {
    return iss;
  }
};

// OpenID4VP presentation consent (docs/oid4vc.md). A standard verifier asked the wallet to prove a
// credential; the user picks which held credential to present (default none), sees the linkability
// caveat, and on approve the wallet builds a vp_token and direct_posts it. Mirrors ApprovalModal's
// verified-credential consent section. `request` = parseAuthorizationRequest(...), `matches` =
// matchCredentialsByScope(...) → [{ cred, disclose }].
const PresentCredentialSheet = ({ request, query, matches, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [chosen, setChosen] = useState(null); // credId to present (default-deny: nothing selected)
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  const present = async () => {
    const match = matches.find((m) => m.cred.credId === chosen);
    if (!match) return;
    setBusy(true);
    try {
      await presentViaOid4vp(masterKey, request, { cred: match.cred, disclose: match.disclose });
      setDone(true);
      showToast('Credential presented.');
    } catch (e) {
      showToast(e.message || 'Could not present.', 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet onClose={onClose} labelledBy="present-title">
      <div className="flex items-center gap-2.5 mb-1">
        <BadgeCheck size={18} className="text-accent" />
        <h2 id="present-title" className="text-lg font-semibold tracking-tight">
          {done ? 'Credential presented' : 'Prove a credential'}
        </h2>
      </div>

      {done ? (
        <>
          <p className="text-[14px] text-muted leading-relaxed mb-6">
            You presented <span className="font-mono text-ink">{(query.disclose || []).join(', ') || query.vct}</span> to{' '}
            <span className="font-mono text-ink">{request.clientId}</span>.
          </p>
          <div className="flex justify-end">
            <Btn variant="primary" onClick={onClose}>
              Done
            </Btn>
          </div>
        </>
      ) : (
        <>
          <p className="text-[14px] text-muted leading-relaxed mb-2">
            <span className="font-mono text-ink">{request.clientId || 'A verifier'}</span> wants you to prove{' '}
            <span className="font-mono text-ink">{(query.disclose || []).join(', ') || query.vct}</span>.
          </p>
          <p className="text-[12px] text-faint leading-relaxed mb-4">
            kunji can't verify who this is — only present to verifiers you trust.
          </p>

          {matches.length === 0 ? (
            <p className="text-[13px] text-faint leading-relaxed mb-6">
              You don't hold a credential that satisfies this request. Receive one from an issuer in
              Security → Verified credentials, then try again.
            </p>
          ) : (
            <>
              <div className="text-[12px] uppercase tracking-wide text-faint mb-2">Choose a credential</div>
              <div className="flex flex-col gap-1.5 mb-4">
                {matches.map(({ cred, disclose }) => {
                  const on = chosen === cred.credId;
                  return (
                    <button
                      key={cred.credId}
                      type="button"
                      onClick={() => setChosen(on ? null : cred.credId)}
                      aria-pressed={on}
                      className={`flex items-start gap-2.5 text-left rounded-xl border px-3 py-2.5 transition-colors ${
                        on ? 'border-accent/40 bg-accent-soft' : 'border-line hover:border-muted'
                      }`}
                    >
                      <span className={`mt-0.5 shrink-0 ${on ? 'text-accent' : 'text-faint'}`}>
                        {on ? <CheckCircle2 size={16} /> : <Circle size={16} />}
                      </span>
                      <span className="min-w-0">
                        <span className="block text-[13px] text-ink">
                          Prove <span className="font-mono">{(disclose || []).join(', ') || cred.vct}</span>
                        </span>
                        <span className="block text-[12px] text-faint truncate">from {issuerHost(cred.iss)}</span>
                      </span>
                    </button>
                  );
                })}
              </div>
              <p className="text-[12px] text-faint leading-relaxed mb-6">
                A verified credential is more identifiable than your random per-app identity — a verifier can
                correlate you across services if you reuse the same one. Only what you choose is shared.
              </p>
            </>
          )}

          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={onClose} disabled={busy}>
              {matches.length === 0 ? 'Close' : 'Cancel'}
            </Btn>
            {matches.length > 0 && (
              <Btn variant="primary" onClick={present} disabled={busy || !chosen}>
                {busy ? 'Presenting…' : 'Present'}
              </Btn>
            )}
          </div>
        </>
      )}
    </Sheet>
  );
};

export default PresentCredentialSheet;
