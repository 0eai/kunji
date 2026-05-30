import React, { useState, useEffect, useRef } from 'react';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { Lock, RotateCcw, ShieldAlert, Key, AlertTriangle } from 'lucide-react';
import { db } from '../lib/firebase';
import {
  deriveKeyFromPasskey, deriveKeyArgon2id, generateSalt, encryptData, decryptData,
  generateMasterKey, exportKey, importMasterKey,
} from '../lib/crypto';
import { resetUserVault } from '../services/vault';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';
import LinkDeviceScreen from './LinkDeviceScreen';
import InstallButton from './InstallButton';

const getDelay = (failCount) => {
  if (failCount <= 0) return 0;
  const delays = [5, 10, 30, 60, 300, 600, 1800, 3600, 14400, 86400];
  return delays[Math.min(failCount - 1, delays.length - 1)];
};

const getStrength = (passkey) => {
  if (!passkey || passkey.length === 0) return { label: '', color: '', width: '0%' };
  let score = 0;
  if (passkey.length >= 8) score++;
  if (passkey.length >= 12) score++;
  if (passkey.length >= 16) score++;
  if (/[A-Z]/.test(passkey) && /[a-z]/.test(passkey)) score++;
  if (/[0-9]/.test(passkey)) score++;
  if (/[^A-Za-z0-9]/.test(passkey)) score++;
  if (score <= 2) return { label: 'Weak', color: 'bg-red-500', width: '25%' };
  if (score <= 3) return { label: 'Fair', color: 'bg-yellow-500', width: '50%' };
  if (score <= 4) return { label: 'Strong', color: 'bg-amber-400', width: '75%' };
  return { label: 'Very Strong', color: 'bg-green-500', width: '100%' };
};

const MIN_PASSKEY_LENGTH = 8;

const LockScreen = ({ user, onUnlock, initialMessage }) => {
  const { showToast } = useToast();
  const [keyInput, setKeyInput] = useState('');
  const [confirmKeyInput, setConfirmKeyInput] = useState('');
  const [isDeriving, setIsDeriving] = useState(false);
  const [status, setStatus] = useState(initialMessage || '');
  const [errorShake, setErrorShake] = useState(false);

  const [failCount, setFailCount] = useState(0);
  const [cooldownEnd, setCooldownEnd] = useState(0);
  const [cooldownRemaining, setCooldownRemaining] = useState(0);
  const timerRef = useRef(null);

  const [isNewUser, setIsNewUser] = useState(null);
  const [isRecovering, setIsRecovering] = useState(false);
  const [isLinking, setIsLinking] = useState(false);
  const [recoveryInput, setRecoveryInput] = useState('');
  const [recoveryPassphrase, setRecoveryPassphrase] = useState('');

  const [showReset, setShowReset] = useState(false);
  const [resetConfirm, setResetConfirm] = useState('');

  useEffect(() => {
    if (!user) return;
    const check = async () => {
      const userDoc = await getDoc(doc(db, 'users', user.uid));
      const data = userDoc.exists() ? userDoc.data() : {};
      setIsNewUser(!data.encryptionSalt || !data.encryptedMasterKey);
    };
    check();
  }, [user]);

  useEffect(() => {
    if (cooldownEnd <= Date.now()) { setCooldownRemaining(0); return; }
    const tick = () => {
      const remaining = Math.ceil((cooldownEnd - Date.now()) / 1000);
      if (remaining <= 0) { setCooldownRemaining(0); clearInterval(timerRef.current); }
      else setCooldownRemaining(remaining);
    };
    tick();
    timerRef.current = setInterval(tick, 500);
    return () => clearInterval(timerRef.current);
  }, [cooldownEnd]);

  const handleKeyDown = (e) => { if (e.key === 'Enter') handleSubmit(e); };

  const handleHardReset = async () => {
    if (resetConfirm.trim().toUpperCase() !== 'RESET') return;
    setShowReset(false);
    setStatus('Wiping data...');
    setIsDeriving(true);
    try {
      await resetUserVault(user.uid);
      logActivity(user.uid, 'Vault Reset', 'danger', 'AlertTriangle');
      showToast('Vault reset. All data erased.');
      window.location.reload();
    } catch (e) {
      showToast('Reset error: ' + e.message, 'error');
      setIsDeriving(false);
      setStatus('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (keyInput.length < MIN_PASSKEY_LENGTH) {
      setStatus(`Passkey must be at least ${MIN_PASSKEY_LENGTH} characters`);
      setErrorShake(true);
      setTimeout(() => setErrorShake(false), 500);
      return;
    }
    if (cooldownRemaining > 0) return;

    setIsDeriving(true);
    setErrorShake(false);
    setStatus('Verifying...');

    try {
      const userDocRef = doc(db, 'users', user.uid);
      const userDoc = await getDoc(userDocRef);
      const userData = userDoc.exists() ? userDoc.data() : {};
      const { encryptionSalt: salt, encryptedMasterKey: encryptedBlob } = userData;

      if (userData.lockoutUntil && userData.lockoutUntil > Date.now()) {
        const remaining = Math.ceil((userData.lockoutUntil - Date.now()) / 1000);
        setCooldownEnd(userData.lockoutUntil);
        setStatus(`Too many attempts. Wait ${remaining}s`);
        setIsDeriving(false);
        return;
      }

      // New vault
      if (!salt || !encryptedBlob) {
        if (keyInput !== confirmKeyInput) {
          setStatus('Passkeys do not match');
          setErrorShake(true);
          setTimeout(() => setErrorShake(false), 500);
          setIsDeriving(false);
          return;
        }
        setStatus('Creating vault...');
        const newSalt = generateSalt();
        const masterKey = await generateMasterKey();
        const wrapperKey = await deriveKeyArgon2id(keyInput, newSalt);
        const masterKeyJWK = await exportKey(masterKey);
        const encryptedMasterKey = await encryptData(masterKeyJWK, wrapperKey);
        const validationPayload = await encryptData({ check: 'VALID' }, masterKey);
        await setDoc(userDocRef, {
          encryptionSalt: newSalt,
          encryptedMasterKey,
          encryptedValidator: validationPayload,
          kdf: 'argon2id',
        }, { merge: true });
        setFailCount(0);
        onUnlock(masterKey);
      }
      // Recovery
      else if (isRecovering) {
        setStatus('Recovering vault...');
        if (keyInput !== confirmKeyInput) {
          setStatus('New passkeys do not match');
          setErrorShake(true);
          setTimeout(() => setErrorShake(false), 500);
          setIsDeriving(false);
          return;
        }
        let masterKeyJWK;
        try {
          const trimmed = recoveryInput.trim();
          if (trimmed.startsWith('v2:')) {
            const payload = JSON.parse(atob(trimmed.slice(3)));
            const { salt: rSalt, ...encryptedJWK } = payload;
            const recoveryWrapperKey = await deriveKeyArgon2id(recoveryPassphrase, rSalt);
            masterKeyJWK = await decryptData(encryptedJWK, recoveryWrapperKey);
            if (!masterKeyJWK) throw new Error('INVALID_RECOVERY_PASSPHRASE');
          } else {
            masterKeyJWK = JSON.parse(atob(trimmed));
          }
        } catch (e) {
          if (e.message === 'INVALID_RECOVERY_PASSPHRASE') throw e;
          throw new Error('INVALID_RECOVERY_KEY');
        }
        const masterKey = await importMasterKey(masterKeyJWK);
        if (userData.encryptedValidator) {
          const check = await decryptData(userData.encryptedValidator, masterKey);
          if (!check || check.check !== 'VALID') throw new Error('INTEGRITY_FAIL');
        }
        setStatus('Securing with new passkey...');
        const newSalt = generateSalt();
        const newWrapperKey = await deriveKeyArgon2id(keyInput, newSalt);
        const newEncryptedMasterKey = await encryptData(masterKeyJWK, newWrapperKey);
        await setDoc(userDocRef, {
          encryptionSalt: newSalt,
          encryptedMasterKey: newEncryptedMasterKey,
          kdf: 'argon2id',
          failedAttempts: 0,
          lockoutUntil: 0,
        }, { merge: true });
        setFailCount(0);
        onUnlock(masterKey);
      }
      // Unlock
      else {
        setStatus('Unlocking...');
        const kdf = userData.kdf || 'pbkdf2';
        const wrapperKey = kdf === 'argon2id'
          ? await deriveKeyArgon2id(keyInput, salt)
          : await deriveKeyFromPasskey(keyInput, salt, userData.iterations);
        const masterKeyJWK = await decryptData(encryptedBlob, wrapperKey);
        if (!masterKeyJWK) throw new Error('WRONG_PASSWORD');
        const masterKey = await importMasterKey(masterKeyJWK);
        if (userData.encryptedValidator) {
          const check = await decryptData(userData.encryptedValidator, masterKey);
          if (!check || check.check !== 'VALID') throw new Error('INTEGRITY_FAIL');
        }
        // Migrate PBKDF2 → Argon2id
        if (kdf !== 'argon2id') {
          const newWrapperKey = await deriveKeyArgon2id(keyInput, salt);
          const newEncryptedMasterKey = await encryptData(masterKeyJWK, newWrapperKey);
          await setDoc(userDocRef, { encryptedMasterKey: newEncryptedMasterKey, kdf: 'argon2id' }, { merge: true });
        }
        if (userData.failedAttempts > 0) {
          await setDoc(userDocRef, { failedAttempts: 0, lockoutUntil: 0 }, { merge: true });
        }
        setFailCount(0);
        onUnlock(masterKey);
      }
    } catch (error) {
      setIsDeriving(false);
      try {
        const userDocRef = doc(db, 'users', user.uid);
        const userDoc = await getDoc(userDocRef);
        const currentData = userDoc.exists() ? userDoc.data() : {};
        const newFailCount = (currentData.failedAttempts || 0) + 1;
        const delay = getDelay(newFailCount);
        const newLockoutUntil = delay > 0 ? Date.now() + delay * 1000 : 0;
        await setDoc(userDocRef, { failedAttempts: newFailCount, lockoutUntil: newLockoutUntil }, { merge: true });
        setFailCount(newFailCount);
        if (delay > 0) { setCooldownEnd(newLockoutUntil); setStatus(`Too many attempts. Wait ${delay}s`); }
        else setStatus('Incorrect Passkey');
      } catch { setStatus('Incorrect Passkey'); }
      setErrorShake(true);
      logActivity(user.uid, 'Failed Passkey Attempt', 'danger', 'AlertTriangle');
      setTimeout(() => setErrorShake(false), 500);
    }
  };

  const strength = (isNewUser || isRecovering) ? getStrength(keyInput) : null;

  if (isLinking) {
    return <LinkDeviceScreen user={user} onUnlock={onUnlock} onCancel={() => setIsLinking(false)} />;
  }

  return (
    <div className="h-[100dvh] w-full flex flex-col items-center justify-center bg-[#09090b] text-white p-6">
      <div className={`bg-[#18181b] p-8 rounded-3xl shadow-2xl max-w-sm w-full border border-[#27272a] transition-transform ${errorShake ? 'animate-shake' : ''}`}>
        <div className="mx-auto w-16 h-16 bg-amber-500 rounded-2xl flex items-center justify-center mb-6 shadow-[0_0_30px_-5px_rgba(245,158,11,0.5)]">
          <Lock size={32} className="text-black" />
        </div>
        <h2 className="text-2xl font-bold mb-1 text-center tracking-tight">
          {isRecovering ? 'Vault Recovery' : isNewUser ? 'Create Vault' : 'Unlock Kunji'}
        </h2>
        <p className={`text-center mb-6 text-sm ${
          status === 'Incorrect Passkey' || status.startsWith('Too many') ? 'text-red-400 font-bold'
          : status === 'Wiping data...' ? 'text-red-400 animate-pulse'
          : status.startsWith('Passkey must') || status.startsWith('New passkey') ? 'text-yellow-400'
          : 'text-gray-400'
        }`}>
          {status || (isNewUser
            ? `Choose a vault passkey (min ${MIN_PASSKEY_LENGTH} chars)`
            : isRecovering ? 'Paste your recovery key and set a new passkey'
            : 'Enter your passkey to decrypt your identity vault'
          )}
        </p>

        <form onSubmit={handleSubmit}>
          {isRecovering && (
            <>
              <textarea
                value={recoveryInput}
                onChange={(e) => { setRecoveryInput(e.target.value); if (status) setStatus(''); }}
                placeholder="Paste your recovery key..."
                className="w-full h-24 p-3 rounded-xl bg-black border border-[#27272a] text-white mb-2 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none placeholder-gray-600 font-mono text-xs resize-none"
                required
              />
              {recoveryInput.trim().startsWith('v2:') && (
                <input
                  type="password"
                  value={recoveryPassphrase}
                  onChange={(e) => { setRecoveryPassphrase(e.target.value); if (status) setStatus(''); }}
                  placeholder="Recovery key passphrase..."
                  className="w-full p-4 rounded-xl bg-black border border-[#27272a] text-white mb-2 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none placeholder-gray-600 font-medium tracking-wide"
                  required
                />
              )}
            </>
          )}

          <input
            type="password"
            value={keyInput}
            onChange={(e) => { setKeyInput(e.target.value); if (status && status !== 'Wiping data...') setStatus(''); }}
            onKeyDown={handleKeyDown}
            placeholder={isNewUser ? 'Choose a Passkey' : isRecovering ? 'New Passkey' : 'Enter Passkey'}
            className="w-full p-4 rounded-xl bg-black border border-[#27272a] text-white mb-2 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none placeholder-gray-600 font-medium tracking-wide"
            autoFocus
          />

          {(isNewUser || isRecovering) && (
            <input
              type="password"
              value={confirmKeyInput}
              onChange={(e) => { setConfirmKeyInput(e.target.value); if (status && status !== 'Wiping data...') setStatus(''); }}
              onKeyDown={handleKeyDown}
              placeholder="Confirm Passkey"
              className="w-full p-4 rounded-xl bg-black border border-[#27272a] text-white mb-2 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none placeholder-gray-600 font-medium tracking-wide"
            />
          )}

          {strength && keyInput.length > 0 && (
            <div className="mb-3">
              <div className="h-1 bg-[#27272a] rounded-full overflow-hidden">
                <div className={`h-full ${strength.color} rounded-full transition-all duration-300`} style={{ width: strength.width }} />
              </div>
              <div className="flex justify-between items-center mt-1.5">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">{strength.label}</span>
                <span className="text-[10px] text-gray-600">{keyInput.length} chars</span>
              </div>
            </div>
          )}

          {!isNewUser && !isRecovering && keyInput.length > 0 && keyInput.length < MIN_PASSKEY_LENGTH && (
            <div className="text-[10px] text-yellow-500/70 mb-2 text-right">{keyInput.length}/{MIN_PASSKEY_LENGTH} min</div>
          )}

          {cooldownRemaining > 0 && (
            <div className="flex items-center justify-center gap-2 bg-red-950/50 text-red-400 text-xs font-bold py-2 px-3 rounded-lg mb-3 border border-red-900/50">
              <ShieldAlert size={14} />
              Locked for {cooldownRemaining}s
            </div>
          )}

          <button
            type="submit"
            disabled={isDeriving || cooldownRemaining > 0}
            className="w-full py-4 bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:cursor-wait text-black rounded-xl font-bold transition-all active:scale-[0.98]"
          >
            {isDeriving ? <span className="animate-pulse">Processing...</span>
              : cooldownRemaining > 0 ? 'Locked'
              : isNewUser ? 'Create Vault'
              : isRecovering ? 'Recover & Unlock'
              : 'Unlock Vault'}
          </button>
        </form>

        {isNewUser && !isRecovering && (
          <button
            onClick={() => setIsLinking(true)}
            className="mt-4 w-full py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white text-sm font-semibold transition-colors"
          >
            Link from another device
          </button>
        )}

        <div className="mt-4">
          <InstallButton />
        </div>

        <div className="mt-8 flex justify-between items-center">
          {!isNewUser && (
            <button
              onClick={() => { setIsRecovering(!isRecovering); setStatus(''); setKeyInput(''); setConfirmKeyInput(''); setRecoveryInput(''); setRecoveryPassphrase(''); }}
              className="text-[10px] uppercase tracking-widest text-amber-400 hover:text-amber-300 flex items-center gap-2 transition-colors font-semibold"
            >
              <Key size={12} /> {isRecovering ? 'Cancel' : 'Forgot Passkey?'}
            </button>
          )}
          <button
            onClick={() => { setResetConfirm(''); setShowReset(true); }}
            className="text-[10px] uppercase tracking-widest text-gray-600 hover:text-red-500 flex items-center gap-2 transition-colors font-semibold ml-auto"
          >
            <RotateCcw size={12} /> Reset Vault
          </button>
        </div>
      </div>
      <style>{`@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-10px)}75%{transform:translateX(10px)}}.animate-shake{animation:shake .4s ease-in-out}`}</style>

      {showReset && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#18181b] border border-red-900/60 rounded-3xl w-full max-w-sm p-6">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-9 h-9 bg-red-500/15 rounded-full flex items-center justify-center">
                <AlertTriangle size={16} className="text-red-400" />
              </div>
              <h2 className="text-lg font-bold text-white">Reset this vault?</h2>
            </div>
            <p className="text-sm text-gray-400 mb-4">
              This <strong className="text-gray-200">permanently erases this device's vault</strong>. Without your
              recovery key or another linked device, your identity can't be recovered.
            </p>
            <label className="block text-xs text-gray-500 mb-1">Type <span className="font-mono text-gray-300">RESET</span> to confirm</label>
            <input
              autoFocus value={resetConfirm}
              onChange={(e) => setResetConfirm(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleHardReset(); }}
              placeholder="RESET"
              className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-700 focus:ring-2 focus:ring-red-600 focus:border-transparent outline-none mb-4"
            />
            <div className="flex gap-2">
              <button
                onClick={() => setShowReset(false)} disabled={isDeriving}
                className="flex-1 py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleHardReset}
                disabled={isDeriving || resetConfirm.trim().toUpperCase() !== 'RESET'}
                className="flex-1 py-3 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold transition-colors"
              >
                {isDeriving ? 'Wiping…' : 'Reset vault'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LockScreen;
