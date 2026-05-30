import React, { useState, useEffect, useRef } from 'react';
import { ScanLine, Lock, KeyRound, Shield, Settings } from 'lucide-react';
import { listenToApps, deleteApp, registerApp, parseQRPayload, submitDiscoverableAssertion, deriveSubFromPublicKey } from '../services/identity';
import { completeLink } from '../services/linking';
import { deriveVaultId } from '../lib/crypto';
import AppCard from './AppCard';
import ApprovalModal from './ApprovalModal';
import AppDetailsModal from './AppDetailsModal';
import QRScannerOverlay from './QRScannerOverlay';
import SecurityPanel from './SecurityPanel';
import { useToast } from '../contexts/ToastContext';

const Dashboard = ({ user, cryptoKey, onLock, incomingApproval }) => {
  const { showToast } = useToast();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [vaultId, setVaultId] = useState(null);

  const [showScanner, setShowScanner] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [pendingSession, setPendingSession] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);
  const [returnInfo, setReturnInfo] = useState(null); // { audience, returnUrl } after same-device approval
  const incomingHandled = useRef(false);

  // Derive the shared vault id from the master key (same on every linked device).
  useEffect(() => {
    deriveVaultId(cryptoKey).then(setVaultId).catch(() => setVaultId(null));
  }, [cryptoKey]);

  useEffect(() => {
    if (!vaultId) return;
    const unsub = listenToApps(vaultId, cryptoKey, (data) => {
      setApps(data);
      setLoading(false);
    });
    return unsub;
  }, [vaultId, cryptoKey]);

  // Same-device deep-link: process an incoming approval payload once the vault is ready.
  useEffect(() => {
    if (!vaultId || !incomingApproval || incomingHandled.current) return;
    incomingHandled.current = true;
    handleQRScan(incomingApproval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, incomingApproval]);

  const handleQRScan = async (rawValue) => {
    setShowScanner(false);

    // A device-link QR ({kunjiLink:'v1'}) — transfer the master key to the new device.
    try {
      const maybeLink = JSON.parse(rawValue);
      if (maybeLink?.kunjiLink === 'v1') {
        try {
          await completeLink(rawValue, cryptoKey);
          showToast('Device linked — it now shares your identity.');
        } catch (e) {
          const m = e.message === 'link_expired' ? 'Link QR expired.'
            : e.message === 'link_already_used' ? 'That link was already used.'
            : 'Linking failed: ' + e.message;
          showToast(m, 'error');
        }
        return;
      }
    } catch { /* not JSON / not a link QR — fall through to login parsing */ }

    try {
      const qr = parseQRPayload(rawValue);

      // Find an existing key for this audience domain, or auto-register one
      // (first login to a domain == registration, fully client-side).
      let matchedApp = apps.find(a => a.domain === qr.audience);
      let isNew = false;
      if (!matchedApp) {
        const { registeredAppId, publicKey } = await registerApp(vaultId, cryptoKey, {
          name: qr.appName || qr.audience,
          domain: qr.audience,
          iconUrl: qr.iconUrl || '',
        }, user.uid);
        matchedApp = { id: registeredAppId, name: qr.appName || qr.audience, domain: qr.audience, publicKey };
        isNew = true;
      }

      const sub = await deriveSubFromPublicKey(matchedApp.publicKey);
      setPendingSession({
        ...qr,
        registeredAppId: matchedApp.id,
        publicKey: matchedApp.publicKey,
        appName: matchedApp.name,
        domain: qr.audience,
        sub,
        isNew,
      });
    } catch (err) {
      const msg = err.message === 'expired_qr' ? 'QR code has expired.'
        : err.message === 'untrusted_callback' ? 'Untrusted login request (callback domain mismatch).'
        : 'Invalid QR code.';
      showToast(msg, 'error');
    }
  };

  const handleApprove = async () => {
    if (!pendingSession) return;
    const { audience, returnUrl } = pendingSession;
    try {
      await submitDiscoverableAssertion(user.uid, cryptoKey, pendingSession);
      showToast(`Signed in to ${audience}`);
      if (returnUrl) setReturnInfo({ audience, returnUrl });
    } catch (e) {
      showToast('Login failed: ' + e.message, 'error');
    } finally {
      setPendingSession(null);
    }
  };

  const handleDeny = () => {
    // No shared session to update — kunji simply declines locally.
    showToast('Login request declined.');
    setPendingSession(null);
  };

  const handleDeleteApp = async (app) => {
    if (!window.confirm(`Remove "${app.name}"?\n\nExisting sessions signed by this app's key will no longer verify.`)) return;
    try {
      await deleteApp(vaultId, app.id, app.name, cryptoKey, user.uid);
      showToast(`Removed ${app.name}`);
    } catch (e) {
      showToast('Delete failed: ' + e.message, 'error');
    }
  };

  return (
    <div className="h-[100dvh] bg-[#09090b] text-white flex flex-col overflow-hidden">
      {/* Header */}
      <header className="flex items-center justify-between px-5 pt-10 pb-4 shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 bg-amber-500 rounded-lg flex items-center justify-center">
            <KeyRound size={18} className="text-black" />
          </div>
          <span className="text-xl font-bold tracking-tight">kunji</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setShowSecurity(true)}
            className="p-2 text-gray-500 hover:text-white transition-colors rounded-lg hover:bg-[#27272a]"
            title="Security"
          >
            <Settings size={16} />
          </button>
          <button
            onClick={onLock}
            className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-[#27272a]"
          >
            <Lock size={13} /> Lock
          </button>
        </div>
      </header>

      {/* App List (scrolls; the Scan QR action is pinned at the bottom) */}
      <div className="flex-1 overflow-y-auto px-5 py-2">
        {loading ? (
          <div className="flex items-center justify-center h-48 text-gray-600">Loading...</div>
        ) : apps.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-[#18181b] border border-[#27272a] flex items-center justify-center">
              <Shield size={28} className="text-gray-600" />
            </div>
            <div>
              <p className="text-gray-400 font-medium">No apps yet</p>
              <p className="text-gray-600 text-sm mt-1">Scan an app's login QR to sign in — it's added here automatically.</p>
            </div>
          </div>
        ) : (
          <div className="space-y-3 pb-8">
            {apps.map(app => (
              <AppCard
                key={app.id}
                app={app}
                onDetails={() => setSelectedApp(app)}
                onDelete={() => handleDeleteApp(app)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Pinned bottom action — primary action in the thumb zone */}
      <div className="shrink-0 px-5 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))] border-t border-[#18181b] bg-[#09090b]">
        <button
          onClick={() => setShowScanner(true)}
          className="w-full flex items-center justify-center gap-2 bg-amber-500 hover:bg-amber-400 text-black font-semibold py-3.5 rounded-2xl transition-all active:scale-[0.97]"
        >
          <ScanLine size={18} /> Scan QR
        </button>
      </div>

      {/* Modals */}
      {showScanner && (
        <QRScannerOverlay
          onScan={handleQRScan}
          onClose={() => setShowScanner(false)}
        />
      )}

      {pendingSession && (
        <ApprovalModal
          session={pendingSession}
          onApprove={handleApprove}
          onDeny={handleDeny}
          onClose={() => setPendingSession(null)}
        />
      )}

      {selectedApp && (
        <AppDetailsModal
          app={selectedApp}
          onClose={() => setSelectedApp(null)}
        />
      )}

      {showSecurity && (
        <SecurityPanel
          userId={user.uid}
          cryptoKey={cryptoKey}
          onLock={onLock}
          onClose={() => setShowSecurity(false)}
        />
      )}

      {returnInfo && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#18181b] border border-[#27272a] rounded-3xl w-full max-w-sm p-6 text-center">
            <div className="mx-auto w-14 h-14 bg-green-500/15 rounded-full flex items-center justify-center mb-4">
              <Shield size={26} className="text-green-400" />
            </div>
            <h2 className="text-lg font-bold text-white mb-1">Signed in</h2>
            <p className="text-sm text-gray-400 mb-5">You approved sign-in to <strong className="text-gray-200">{returnInfo.audience}</strong>.</p>
            <a
              href={returnInfo.returnUrl}
              className="block w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors"
            >
              Return to {returnInfo.audience}
            </a>
            <button onClick={() => setReturnInfo(null)} className="mt-2 w-full py-2.5 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white text-sm font-medium transition-colors">
              Stay in kunji
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
