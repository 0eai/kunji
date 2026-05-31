// src/contexts/VaultContext.jsx
// Single Source of Truth for authentication and vault encryption state.
// Auto-lock logic lives in App.jsx (configurable timer + lock-on-hidden).
// This context only holds state; it does NOT manage timers or side-effects.
import React, { createContext, useContext, useState, useCallback } from 'react';

const VaultContext = createContext();

export const VaultProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [cryptoKey, setCryptoKey] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lockReason, setLockReason] = useState("");

  // Lock vault: clear key + optionally set a reason message
  const lockVault = useCallback((reason = "") => {
    setLockReason(reason);
    setCryptoKey(null);
  }, []);

  // Unlock vault: set key + clear any lock reason
  const unlockVault = useCallback((key) => {
    setLockReason("");
    setCryptoKey(key);
  }, []);

  // Auth state setter (called from App.jsx onAuthStateChanged)
  const setAuthUser = useCallback((u) => {
    setUser(u);
    setLoading(false);
    if (!u) {
      setCryptoKey(null);
      setLockReason("");
    }
  }, []);

  return (
    <VaultContext.Provider value={{
      user, cryptoKey, loading, lockReason,
      setAuthUser, setCryptoKey, unlockVault, lockVault
    }}>
      {children}
    </VaultContext.Provider>
  );
};

export const useVault = () => useContext(VaultContext);
