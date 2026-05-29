import React, { useEffect } from 'react';
import { useVault } from './context/VaultContext';
import { auth, ensureAnonymousAuth, onAuthStateChanged } from './lib/firebase';
import { logActivity } from './services/activityLog';
import LockScreen from './components/LockScreen';
import Dashboard from './components/Dashboard';

export default function App() {
  const { user, cryptoKey, loading, lockReason, setAuthUser, unlockVault, lockVault } = useVault();

  // Sign in anonymously on first load, persist session
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        setAuthUser(firebaseUser);
      } else {
        try {
          const anonUser = await ensureAnonymousAuth();
          setAuthUser(anonUser);
        } catch (e) {
          console.error('Anonymous auth failed:', e);
        }
      }
    });
    return unsub;
  }, [setAuthUser]);

  // Auto-lock on inactivity (default 20 hours, stored in localStorage as kunji_autolock minutes)
  useEffect(() => {
    if (!cryptoKey || !user) return;
    const getTimeout = () => {
      const saved = localStorage.getItem('kunji_autolock');
      const minutes = saved ? parseInt(saved) : 1200;
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
    events.forEach(e => window.addEventListener(e, resetTimer, { passive: true }));
    return () => {
      if (timer) clearTimeout(timer);
      events.forEach(e => window.removeEventListener(e, resetTimer));
    };
  }, [cryptoKey, user, lockVault]);

  // Lock when tab is hidden (opt-in, stored in localStorage as kunji_lock_on_hidden)
  useEffect(() => {
    if (!cryptoKey || !user) return;
    const handle = () => {
      if (localStorage.getItem('kunji_lock_on_hidden') === 'true' && document.visibilityState === 'hidden') {
        logActivity(user.uid, 'Vault Auto-Locked (Hidden)', 'info', 'Lock', cryptoKey);
        lockVault('Locked because the tab was hidden.');
      }
    };
    document.addEventListener('visibilitychange', handle);
    return () => document.removeEventListener('visibilitychange', handle);
  }, [cryptoKey, user, lockVault]);

  if (loading) {
    return (
      <div className="h-[100dvh] w-full flex items-center justify-center bg-[#09090b]">
        <div className="w-8 h-8 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="h-[100dvh] w-full flex items-center justify-center bg-[#09090b] text-gray-500 text-sm">
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
          logActivity(user.uid, 'Vault Unlocked', 'success', 'Unlock');
        }}
        initialMessage={lockReason || ''}
      />
    );
  }

  return (
    <Dashboard
      user={user}
      cryptoKey={cryptoKey}
      onLock={() => {
        logActivity(user.uid, 'Vault Locked', 'info', 'Lock', cryptoKey);
        lockVault();
      }}
    />
  );
}
