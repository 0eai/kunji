import React, { useEffect, useState } from 'react';
import { useVault } from './contexts/VaultContext';
import { auth, ensureAnonymousAuth, onAuthStateChanged } from './lib/firebase';
import { logActivity } from './services/activityLog';
import LockScreen from './components/LockScreen';
import Dashboard from './components/Dashboard';

// Default auto-lock timeout in minutes (20 hours) when the user hasn't set one.
const AUTO_LOCK_DEFAULT_MIN = 1200;

// Decode one base64url(JSON) query param into its JSON string (validated), or null.
function decodeB64urlParam(name) {
  try {
    const raw = new URLSearchParams(window.location.search).get(name);
    if (!raw) return null;
    const json = atob(raw.replace(/-/g, '+').replace(/_/g, '/'));
    JSON.parse(json); // validate it's JSON
    return json;
  } catch {
    return null;
  }
}

// Same-device deep links an RP/agent/verifier/issuer can open:
//   app.kunji.cc/?approve=<base64url(JSON login QR)>        → the login approval modal
//   app.kunji.cc/?authorize=<base64url(JSON agent request)> → the agent re-consent sheet (step-up)
//   app.kunji.cc/?vp=<url-encoded openid4vp:// request>     → the OpenID4VP present sheet
//   app.kunji.cc/?offer=<url-encoded openid-credential-offer:// uri> → the OpenID4VCI receive-offer sheet
// Decode once at startup; clear the query so a refresh doesn't replay it.
function readIncomingLinks() {
  const approve = decodeB64urlParam('approve');
  const authorize = decodeB64urlParam('authorize');
  // The OpenID4VP request / OpenID4VCI offer are URIs (not JSON); URLSearchParams decodes the value for us.
  const vpRaw = new URLSearchParams(window.location.search).get('vp');
  const vp = vpRaw && vpRaw.startsWith('openid4vp://') ? vpRaw : null;
  const offerRaw = new URLSearchParams(window.location.search).get('offer');
  const offer = offerRaw && offerRaw.startsWith('openid-credential-offer://') ? offerRaw : null;
  // A Web Push notification opens app.kunji.cc/?push=<requestId> (the agent-request relay code).
  const pushRaw = new URLSearchParams(window.location.search).get('push');
  const push = pushRaw && /^\d{6}$/.test(pushRaw) ? pushRaw : null;
  if (approve || authorize || vp || offer || push) history.replaceState(null, '', window.location.pathname);
  return { approve, authorize, vp, offer, push };
}

export default function App() {
  const { user, cryptoKey, loading, lockReason, setAuthUser, unlockVault, lockVault } = useVault();
  const [incoming] = useState(readIncomingLinks);
  const [authError, setAuthError] = useState(false);

  // Sign in anonymously on first load, persist session
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        setAuthUser(firebaseUser);
        setAuthError(false);
      } else {
        try {
          const anonUser = await ensureAnonymousAuth();
          setAuthUser(anonUser);
          setAuthError(false);
        } catch (e) {
          console.error('Anonymous auth failed:', e);
          setAuthError(true);
        }
      }
    });
    return unsub;
  }, [setAuthUser]);

  // If no session is established within a few seconds (blocked storage, offline,
  // private mode), surface an actionable error instead of a perpetual "Connecting…".
  useEffect(() => {
    if (user) return;
    const t = setTimeout(() => setAuthError(true), 8000);
    return () => clearTimeout(t);
  }, [user]);

  // Auto-lock on inactivity (default 20 hours, stored in localStorage as kunji_autolock minutes)
  useEffect(() => {
    if (!cryptoKey || !user) return;
    const getTimeout = () => {
      const saved = localStorage.getItem('kunji_autolock');
      const minutes = saved ? parseInt(saved) : AUTO_LOCK_DEFAULT_MIN;
      return minutes === 0 ? null : minutes * 60000;
    };
    let timer = null;
    const resetTimer = () => {
      if (timer) clearTimeout(timer);
      const timeout = getTimeout();
      if (timeout) {
        timer = setTimeout(() => {
          logActivity(user.uid, 'Vault Auto-Locked', 'info', 'Lock', cryptoKey);
          lockVault('Session expired due to inactivity.');
        }, timeout);
      }
    };
    resetTimer();
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((e) => window.addEventListener(e, resetTimer, { passive: true }));
    return () => {
      if (timer) clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, resetTimer));
    };
  }, [cryptoKey, user, lockVault]);

  // Lock when tab is hidden (opt-in, stored in localStorage as kunji_lock_on_hidden)
  useEffect(() => {
    if (!cryptoKey || !user) return;
    const handle = () => {
      if (
        localStorage.getItem('kunji_lock_on_hidden') === 'true' &&
        document.visibilityState === 'hidden'
      ) {
        logActivity(user.uid, 'Vault Auto-Locked (Hidden)', 'info', 'Lock', cryptoKey);
        lockVault('Locked because the tab was hidden.');
      }
    };
    document.addEventListener('visibilitychange', handle);
    return () => document.removeEventListener('visibilitychange', handle);
  }, [cryptoKey, user, lockVault]);

  if (loading) {
    return (
      <div className="h-[100dvh] w-full flex items-center justify-center bg-paper">
        <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!user) {
    if (authError) {
      return (
        <div className="h-[100dvh] w-full flex flex-col items-center justify-center gap-4 bg-paper text-ink px-6 text-center">
          <p className="text-[15px] font-medium">Couldn't connect</p>
          <p className="text-[14px] text-muted max-w-xs leading-relaxed">
            kunji needs storage and network access. Check your connection, and if you're in private
            mode or have strict tracking protection on, allow this site.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center justify-center px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full transition-colors"
          >
            Try again
          </button>
        </div>
      );
    }
    return (
      <div className="h-[100dvh] w-full flex items-center justify-center bg-paper text-faint text-sm">
        Connecting…
      </div>
    );
  }

  if (!cryptoKey) {
    return (
      <LockScreen
        user={user}
        onUnlock={(key) => {
          unlockVault(key);
          logActivity(user.uid, 'Vault Unlocked', 'success', 'Unlock', key);
        }}
        initialMessage={lockReason || ''}
      />
    );
  }

  return (
    <Dashboard
      user={user}
      cryptoKey={cryptoKey}
      incomingApproval={incoming.approve}
      incomingAuthorize={incoming.authorize}
      incomingPresentation={incoming.vp}
      incomingOffer={incoming.offer}
      incomingPush={incoming.push}
      onLock={() => {
        logActivity(user.uid, 'Vault Locked', 'info', 'Lock', cryptoKey);
        lockVault();
      }}
    />
  );
}
