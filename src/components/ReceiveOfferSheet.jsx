import React, { useState } from 'react';
import { DownloadCloud } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn } from './ui/primitives';
import { receiveViaOffer, offerNeedsSignIn, beginAuthCodeFlow } from '../services/credentials';
import { parseCredentialOffer } from '../lib/oid4vc';
import { useToast } from '../contexts/ToastContext';

const issuerHost = (iss) => {
  try {
    return new URL(iss).host;
  } catch {
    return iss || 'an issuer';
  }
};

// OpenID4VCI receive-offer consent (docs/oid4vc.md). Reached from the top-level QR scanner or the
// `?offer=` same-device deep link — the symmetric one-tap counterpart to the `?vp=` present sheet. The
// user sees who's issuing and confirms; on approve the wallet redeems the offer via `receiveViaOffer`
// (which already enforces the https-issuer guard [S21]) and stores the credential. Receiving is
// low-stakes — an issuer-signed credential lands in the vault; nothing leaves it.
const ReceiveOfferSheet = ({ offer, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [busy, setBusy] = useState(false);
  let host = 'an issuer';
  try {
    host = issuerHost(parseCredentialOffer(offer).credentialIssuer);
  } catch {
    /* malformed offer — the receive call below surfaces the error */
  }
  // An authorization_code offer can't be redeemed in place — it needs the sign-in (redirect) on-ramp.
  const needsSignIn = offerNeedsSignIn(offer);

  const receive = async () => {
    setBusy(true);
    try {
      if (needsSignIn) {
        // Leg 1: persist the PKCE context, then navigate the tab to the issuer's /authorize. The issuer
        // redirects back to ?code=&state=, which the wallet completes after re-unlock (Dashboard).
        const url = await beginAuthCodeFlow(offer);
        window.location.assign(url);
        return; // navigating away — leave `busy` set
      }
      const r = await receiveViaOffer(masterKey, offer);
      showToast(r?.count > 1 ? `Received ${r.count} single-use copies.` : 'Credential received.');
      onClose();
    } catch (e) {
      showToast(e.message || 'Could not accept the offer.', 'error');
      setBusy(false);
    }
  };

  return (
    <Sheet onClose={onClose} labelledBy="offer-title">
      <div className="flex items-center gap-2.5 mb-1">
        <DownloadCloud size={18} className="text-accent" />
        <h2 id="offer-title" className="text-lg font-semibold tracking-tight">
          Receive a credential
        </h2>
      </div>

      <p className="text-[14px] text-muted leading-relaxed mb-2">
        <span className="font-mono text-ink">{host}</span> wants to issue you a verified credential into your
        wallet.
      </p>
      <p className="text-[12px] text-faint leading-relaxed mb-6">
        kunji can't vouch for this issuer — only accept credentials from sources you trust. The credential
        stays in your wallet; nothing is shared until you choose to present it.
        {needsSignIn && (
          <>
            {' '}
            This issuer asks you to <span className="text-muted">sign in</span> first — you'll be sent to{' '}
            <span className="font-mono">{host}</span> and returned to finish.
          </>
        )}
      </p>

      <div className="flex gap-3">
        <Btn variant="ghost" onClick={onClose} disabled={busy} className="flex-1">
          Cancel
        </Btn>
        <Btn variant="primary" onClick={receive} disabled={busy} className="flex-1">
          {needsSignIn ? (busy ? 'Redirecting…' : 'Sign in to receive') : busy ? 'Receiving…' : 'Receive'}
        </Btn>
      </div>
    </Sheet>
  );
};

export default ReceiveOfferSheet;
