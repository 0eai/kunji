import React, { useState, useEffect, useRef, lazy, Suspense } from 'react';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { Key, AlertTriangle, ArrowRight } from 'lucide-react';
import { db } from '../lib/firebase';
import {
  deriveKeyFromPasskey, deriveKeyArgon2id, generateSalt, encryptData, decryptData,
  generateMasterKey, exportKey, importMasterKey,
  ARGON2_DEFAULTS, ARGON2_LEGACY, argon2ParamsFromDoc, argon2DocFields,
} from '../lib/crypto';
import { resetUserVault } from '../services/vault';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';
import InstallButton from './InstallButton';
// Lazy: pulls in the qrcode lib + linking flow only when the user links a device.
const LinkDeviceScreen = lazy(() => import('./LinkDeviceScreen'));
const LazyFallback = () => (
  <div className="h-[100dvh] w-full flex items-center justify-center bg-paper">
    <div className="w-7 h-7 border-2 border-accent border-t-transparent rounded-full animate-spin" />
  </div>
);
import Sheet from './ui/Sheet';
import { Field, PasswordField, Btn, Spinner } from './ui/primitives';

// NOTE: this failed-attempt backoff is a soft UX throttle only — the lockout fields
// live in the user's own (client-writable) Firestore doc and can be reset by the user,
// and an offline attacker with the encrypted blob never touches this code. The real
// brute-force defense is the Argon2id KDF cost (see deriveKeyArgon2id). Do not treat
// this as a security control.
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
  if (score <= 2) return { label: 'Weak', color: 'bg-danger', width: '25%' };
  if (score <= 3) return { label: 'Fair', color: 'bg-accent-fill', width: '50%' };
  if (score <= 4) return { label: 'Strong', color: 'bg-accent', width: '75%' };
  return { label: 'Very strong', color: 'bg-success', width: '100%' };
};

const MIN_PASSKEY_LENGTH = 10;

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
        if (getStrength(keyInput).label === 'Weak') {
          setStatus('Choose a stronger passkey');
          setErrorShake(true);
          setTimeout(() => setErrorShake(false), 500);
          setIsDeriving(false);
          return;
        }
        setStatus('Creating vault...');
        const newSalt = generateSalt();
        const masterKey = await generateMasterKey();
        let wrapperKey;
        try {
          wrapperKey = await deriveKeyArgon2id(keyInput, newSalt); // V2
        } catch {
          setStatus('This device ran low on memory creating the vault. Try another device.');
          setIsDeriving(false);
          return;
        }
        const masterKeyJWK = await exportKey(masterKey);
        const encryptedMasterKey = await encryptData(masterKeyJWK, wrapperKey);
        const validationPayload = await encryptData({ check: 'VALID' }, masterKey);
        await setDoc(userDocRef, {
          encryptionSalt: newSalt,
          encryptedMasterKey,
          encryptedValidator: validationPayload,
          kdf: 'argon2id',
          argon2: argon2DocFields(ARGON2_DEFAULTS),
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
        if (getStrength(keyInput).label === 'Weak') {
          setStatus('Choose a stronger passkey');
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
            // Recovery blobs carry their own Argon2id params (legacy if absent).
            const { salt: rSalt, argon2: rArgon, ...encryptedJWK } = payload;
            const rParams = rArgon ? { memorySize: rArgon.m, iterations: rArgon.t, parallelism: rArgon.p } : ARGON2_LEGACY;
            const recoveryWrapperKey = await deriveKeyArgon2id(recoveryPassphrase, rSalt, rParams);
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
        const newWrapperKey = await deriveKeyArgon2id(keyInput, newSalt); // V2
        const newEncryptedMasterKey = await encryptData(masterKeyJWK, newWrapperKey);
        await setDoc(userDocRef, {
          encryptionSalt: newSalt,
          encryptedMasterKey: newEncryptedMasterKey,
          kdf: 'argon2id',
          argon2: argon2DocFields(ARGON2_DEFAULTS),
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
        const params = argon2ParamsFromDoc(userData); // legacy params if no `argon2` field
        const wrapperKey = kdf === 'argon2id'
          ? await deriveKeyArgon2id(keyInput, salt, params)
          : await deriveKeyFromPasskey(keyInput, salt, userData.iterations);
        const masterKeyJWK = await decryptData(encryptedBlob, wrapperKey);
        if (!masterKeyJWK) throw new Error('WRONG_PASSWORD');
        const masterKey = await importMasterKey(masterKeyJWK);
        if (userData.encryptedValidator) {
          const check = await decryptData(userData.encryptedValidator, masterKey);
          if (!check || check.check !== 'VALID') throw new Error('INTEGRITY_FAIL');
        }
        // Migrate to the current KDF strength (pbkdf2 → argon2id, or legacy argon2 → V2).
        // Best-effort: if this device can't derive the stronger key (e.g. 256MB OOM),
        // leave the vault on its current params — it still unlocks. Never half-migrate.
        const needsUpgrade = kdf !== 'argon2id'
          || params.memorySize < ARGON2_DEFAULTS.memorySize
          || params.iterations < ARGON2_DEFAULTS.iterations;
        if (needsUpgrade) {
          try {
            const newWrapperKey = await deriveKeyArgon2id(keyInput, salt, ARGON2_DEFAULTS);
            const newEncryptedMasterKey = await encryptData(masterKeyJWK, newWrapperKey);
            await setDoc(userDocRef, {
              encryptedMasterKey: newEncryptedMasterKey,
              kdf: 'argon2id',
              argon2: argon2DocFields(ARGON2_DEFAULTS),
            }, { merge: true });
          } catch { /* device can't do V2 — stay on current params, already unlocked */ }
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
    return (
      <Suspense fallback={<LazyFallback />}>
        <LinkDeviceScreen user={user} onUnlock={onUnlock} onCancel={() => setIsLinking(false)} />
      </Suspense>
    );
  }

  const isError = status === 'Incorrect Passkey' || status.startsWith('Too many') || status === 'Wiping data...';
  const isWarn = status.startsWith('Passkey must') || status.startsWith('New passkey') || status === 'Passkeys do not match';
  const heading = isRecovering ? 'Vault recovery' : isNewUser ? 'Create your vault' : 'Welcome back';
  const subtitle = status || (isNewUser
    ? `Choose a passkey to encrypt your identity vault (min ${MIN_PASSKEY_LENGTH} characters).`
    : isRecovering ? 'Paste your recovery key and set a new passkey.'
    : 'Enter your passkey to unlock your identity vault.');

  return (
    <div className="min-h-[100dvh] w-full flex flex-col bg-paper text-ink">
      {/* wordmark */}
      <header className="flex items-center gap-2 px-6 pt-[max(1.25rem,env(safe-area-inset-top))]">
        <img src="/icons/icon.svg" alt="" className="w-6 h-6" />
        <span className="text-[15px] font-semibold tracking-tight lowercase">kunji</span>
      </header>

      {/* focused unlock moment */}
      <main className={`flex-1 flex flex-col justify-center max-w-[26rem] w-full mx-auto px-6 animate-rise ${errorShake ? 'animate-shake' : ''}`}>
        <div className="mb-9">
          <div className="w-12 h-12 rounded-2xl bg-accent-soft flex items-center justify-center mb-6">
            <Key size={22} className="text-accent" strokeWidth={2.25} />
          </div>
          <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-tight mb-2">{heading}</h1>
          <p className={`text-[15px] leading-relaxed min-h-[2.75rem] ${isError ? 'text-danger' : isWarn ? 'text-accent' : 'text-muted'}`}>
            {subtitle}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRecovering && (
            <>
              <textarea
                value={recoveryInput}
                onChange={(e) => { setRecoveryInput(e.target.value); if (status) setStatus(''); }}
                placeholder="Paste your recovery key…"
                className="w-full h-24 bg-transparent border-0 border-b border-line rounded-none px-0 py-3 text-ink placeholder:text-faint outline-none focus:border-accent font-mono text-xs resize-none transition-colors"
                required
              />
              {recoveryInput.trim().startsWith('v2:') && (
                <PasswordField
                  label="Recovery key passphrase"
                  value={recoveryPassphrase}
                  onChange={(e) => { setRecoveryPassphrase(e.target.value); if (status) setStatus(''); }}
                  required
                />
              )}
            </>
          )}

          <PasswordField
            label={isNewUser ? 'Choose a passkey' : isRecovering ? 'New passkey' : 'Passkey'}
            value={keyInput}
            onChange={(e) => { setKeyInput(e.target.value); if (status && status !== 'Wiping data...') setStatus(''); }}
            onKeyDown={handleKeyDown}
            className="text-lg"
            autoFocus
          />

          {(isNewUser || isRecovering) && (
            <PasswordField
              label="Confirm passkey"
              value={confirmKeyInput}
              onChange={(e) => { setConfirmKeyInput(e.target.value); if (status && status !== 'Wiping data...') setStatus(''); }}
              onKeyDown={handleKeyDown}
              className="text-lg"
            />
          )}

          {/* indicator + button as one unit; the slot holds a constant height so
              the button never shifts as strength / char-count appear */}
          <div className="pt-2">
            <div className="h-7">
              {strength && keyInput.length > 0 ? (
                <div>
                  <div className="h-px bg-line overflow-hidden">
                    <div className={`h-full ${strength.color} transition-all duration-300`} style={{ width: strength.width }} />
                  </div>
                  <div className="flex justify-between items-center mt-1.5">
                    <span className="text-[11px] text-muted uppercase tracking-[0.14em]">{strength.label}</span>
                    <span className="text-[11px] font-mono text-faint tabular">{keyInput.length}</span>
                  </div>
                </div>
              ) : (!isNewUser && !isRecovering && keyInput.length > 0 && keyInput.length < MIN_PASSKEY_LENGTH) ? (
                <div className="text-right text-[11px] font-mono text-faint tabular">{keyInput.length}/{MIN_PASSKEY_LENGTH}</div>
              ) : null}
            </div>

            <Btn type="submit" disabled={isDeriving || cooldownRemaining > 0} className="w-full mt-1">
              {isDeriving ? <><Spinner /> {isNewUser ? 'Creating…' : isRecovering ? 'Recovering…' : 'Unlocking…'}</>
                : cooldownRemaining > 0 ? <span className="tabular">Locked · {cooldownRemaining}s</span>
                : isNewUser ? 'Create vault'
                : isRecovering ? 'Recover & unlock'
                : <>Unlock <ArrowRight size={16} strokeWidth={1.75} /></>}
            </Btn>
          </div>
        </form>

        {isNewUser && !isRecovering && (
          <button
            onClick={() => setIsLinking(true)}
            className="mt-5 w-full text-center text-sm font-medium text-accent hover:text-ink transition-colors"
          >
            Link from another device
          </button>
        )}

        <div className="mt-5"><InstallButton /></div>
      </main>

      {/* quiet footer links */}
      <footer className="max-w-[26rem] w-full mx-auto px-6 pb-[max(1.5rem,env(safe-area-inset-bottom))]">
        <div className="flex items-center justify-between border-t border-line pt-4 text-[12px]">
          {!isNewUser ? (
            <button
              onClick={() => { setIsRecovering(!isRecovering); setStatus(''); setKeyInput(''); setConfirmKeyInput(''); setRecoveryInput(''); setRecoveryPassphrase(''); }}
              className="text-muted hover:text-accent transition-colors font-medium"
            >
              {isRecovering ? 'Cancel recovery' : 'Forgot passkey?'}
            </button>
          ) : <span />}
          <button
            onClick={() => { setResetConfirm(''); setShowReset(true); }}
            className="text-faint hover:text-danger transition-colors font-medium"
          >
            Reset vault
          </button>
        </div>
      </footer>

      {showReset && (
        <Sheet onClose={() => !isDeriving && setShowReset(false)} z={60} labelledBy="reset-title">
          <div className="flex items-center gap-2.5 mb-3">
            <AlertTriangle size={18} className="text-danger" />
            <h2 id="reset-title" className="text-lg font-semibold tracking-tight">Reset this vault?</h2>
          </div>
          <p className="text-[14px] text-muted leading-relaxed mb-5">
            This <strong className="text-ink font-medium">permanently erases this device's vault</strong>. Without your
            recovery key or another linked device, your identity can't be recovered.
          </p>
          <label className="block text-[11px] uppercase tracking-[0.14em] text-faint mb-1">
            Type <span className="font-mono normal-case text-muted">RESET</span> to confirm
          </label>
          <Field
            autoFocus value={resetConfirm} mono
            onChange={(e) => setResetConfirm(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleHardReset(); }}
            placeholder="RESET"
            className="mb-6"
          />
          <div className="flex items-center justify-end gap-1">
            <Btn variant="quiet" onClick={() => setShowReset(false)} disabled={isDeriving}>Cancel</Btn>
            <Btn variant="danger" onClick={handleHardReset} disabled={isDeriving || resetConfirm.trim().toUpperCase() !== 'RESET'}>
              {isDeriving ? 'Wiping…' : 'Reset vault'}
            </Btn>
          </div>
        </Sheet>
      )}
    </div>
  );
};

export default LockScreen;
