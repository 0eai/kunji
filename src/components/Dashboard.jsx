import React, { useState, useEffect } from 'react';
import { Plus, ScanLine, Lock, KeyRound, Globe, Shield } from 'lucide-react';
import { listenToApps, deleteApp, registerApp, parseQRPayload, submitDiscoverableAssertion, deriveSubFromPublicKey } from '../services/identity';
import AppCard from './AppCard';
import RegisterAppModal from './RegisterAppModal';
import ApprovalModal from './ApprovalModal';
import AppDetailsModal from './AppDetailsModal';
import QRScannerOverlay from './QRScannerOverlay';
import { useToast } from '../contexts/ToastContext';

const Dashboard = ({ user, cryptoKey, onLock }) => {
  const { showToast } = useToast();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);

  const [showRegister, setShowRegister] = useState(false);
  const [showScanner, setShowScanner] = useState(false);
  const [pendingSession, setPendingSession] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);

  useEffect(() => {
    const unsub = listenToApps(user.uid, cryptoKey, (data) => {
      setApps(data);
      setLoading(false);
    });
    return unsub;
  }, [user.uid, cryptoKey]);

  const handleQRScan = async (rawValue) => {
    setShowScanner(false);
    try {
      const qr = parseQRPayload(rawValue);

      // Find an existing key for this audience domain, or auto-register one
      // (first login to a domain == registration, fully client-side).
      let matchedApp = apps.find(a => a.domain === qr.audience);
      let isNew = false;
      if (!matchedApp) {
        const { registeredAppId, publicKey } = await registerApp(user.uid, cryptoKey, {
          name: qr.appName || qr.audience,
          domain: qr.audience,
          iconUrl: qr.iconUrl || '',
        });
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
    try {
      await submitDiscoverableAssertion(
        user.uid, cryptoKey,
        { registeredAppId: pendingSession.registeredAppId, publicKey: pendingSession.publicKey },
        pendingSession,
      );
      showToast(`Signed in to ${pendingSession.audience}`);
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
      await deleteApp(user.uid, app.id, app.name, cryptoKey);
      showToast(`Removed ${app.name}`);
    } catch (e) {
      showToast('Delete failed: ' + e.message, 'error');
    }
  };

  return (
    <div className="min-h-[100dvh] bg-[#09090b] text-white flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-5 pt-10 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 bg-amber-500 rounded-lg flex items-center justify-center">
            <KeyRound size={18} className="text-black" />
          </div>
          <span className="text-xl font-bold tracking-tight">kunji</span>
        </div>
        <button
          onClick={onLock}
          className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-[#27272a]"
        >
          <Lock size={13} /> Lock
        </button>
      </header>

      {/* Actions */}
      <div className="flex gap-3 px-5 py-3">
        <button
          onClick={() => setShowScanner(true)}
          className="flex-1 flex items-center justify-center gap-2 bg-amber-500 hover:bg-amber-400 text-black font-semibold py-3.5 rounded-2xl transition-all active:scale-[0.97]"
        >
          <ScanLine size={18} /> Scan QR
        </button>
        <button
          onClick={() => setShowRegister(true)}
          className="flex items-center justify-center gap-2 bg-[#27272a] hover:bg-[#3f3f46] text-white font-semibold py-3.5 px-5 rounded-2xl transition-all active:scale-[0.97]"
        >
          <Plus size={18} /> Register App
        </button>
      </div>

      {/* App List */}
      <div className="flex-1 px-5 py-2">
        {loading ? (
          <div className="flex items-center justify-center h-48 text-gray-600">Loading...</div>
        ) : apps.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-[#18181b] border border-[#27272a] flex items-center justify-center">
              <Shield size={28} className="text-gray-600" />
            </div>
            <div>
              <p className="text-gray-400 font-medium">No apps registered</p>
              <p className="text-gray-600 text-sm mt-1">Register an app to get its public key, then scan its QR code to approve logins.</p>
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

      {/* Modals */}
      {showRegister && (
        <RegisterAppModal
          user={user}
          cryptoKey={cryptoKey}
          onClose={() => setShowRegister(false)}
          onRegistered={(app) => {
            setShowRegister(false);
            setSelectedApp(app);
          }}
        />
      )}

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
    </div>
  );
};

export default Dashboard;
