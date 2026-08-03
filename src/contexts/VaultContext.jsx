// src/contexts/VaultContext.jsx
// Single Source of Truth for authentication and vault encryption state.
// Auto-lock logic lives in App.jsx (configurable timer + lock-on-hidden).
// This context holds state and does NOT manage timers. Its one side-effect is clearing any saved
// device session on lock: every lock path funnels through here, so putting it anywhere else would
// let some future caller lock the vault while leaving a restorable key on disk.
import React, { createContext, useContext, useState, useCallback } from 'react';
import { clearDeviceSession } from '../services/deviceSession';
import { revokeSessionSeen } from '../lib/sessionPrefs';

const VaultContext = createContext();

export const VaultProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [cryptoKey, setCryptoKey] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lockReason, setLockReason] = useState('');

  // Lock vault: clear key + optionally set a reason message. "Stay unlocked" survives closing the
  // app, never a lock — so drop the saved session too. revokeSessionSeen FIRST and synchronously:
  // it is the durable half. The IndexedDB delete is async, so a tab frozen or killed in the next
  // moment (lock-on-hidden especially) could leave the record behind — the revoked marker makes
  // restoreDeviceSession refuse it anyway.
  const lockVault = useCallback((reason = '') => {
    revokeSessionSeen();
    clearDeviceSession();
    setLockReason(reason);
    setCryptoKey(null);
  }, []);

  // Unlock vault: set key + clear any lock reason
  const unlockVault = useCallback((key) => {
    setLockReason('');
    setCryptoKey(key);
  }, []);

  // Auth state setter (called from App.jsx onAuthStateChanged)
  const setAuthUser = useCallback((u) => {
    setUser(u);
    setLoading(false);
    if (!u) {
      // Signed out — a restorable key for a gone account must not linger.
      revokeSessionSeen();
      clearDeviceSession();
      setCryptoKey(null);
      setLockReason('');
    }
  }, []);

  return (
    <VaultContext.Provider
      value={{
        user,
        cryptoKey,
        loading,
        lockReason,
        setAuthUser,
        setCryptoKey,
        unlockVault,
        lockVault,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
};

export const useVault = () => useContext(VaultContext);
