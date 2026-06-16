import React, { useState, useRef, useEffect } from 'react';
import { KeyRound, Copy, CheckCircle2, AlertTriangle, Download } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, PasswordField, SheetHeading } from './ui/primitives';
import {
  exportRecoveryKey,
  buildRecoveryEnvelope,
  recoveryFileName,
} from '../services/vault';
import { getStrength } from '../lib/passkeyStrength';
import { useToast } from '../contexts/ToastContext';

const MIN_PASSPHRASE = 12;
const CLEAR_MS = 60000;

// Cold-backup export: re-wrap the master key under a separate recovery passphrase, then reveal the
// v2: string (auto-clears in 60s) and offer copy + a downloadable .kunji file. Mirrors the sheet
// pattern. No crypto here beyond calling exportRecoveryKey — derivation lives in services/vault.
const RecoveryKeySheet = ({ userId, onClose }) => {
  const { showToast } = useToast();
  const [passkey, setPasskey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const clearTimer = useRef(null);

  useEffect(() => () => clearTimeout(clearTimer.current), []);

  const handleGenerate = async () => {
    // Passkey correctness is verified by decryption inside exportRecoveryKey, so this is just a
    // non-empty guard — don't length-gate it (a legacy passkey may predate MIN_PASSKEY_LENGTH).
    // The recovery passphrase is the lock on a downloadable, offline-attackable file, so it gets
    // the higher MIN_PASSPHRASE floor.
    if (!passkey) {
      showToast('Enter your current passkey.', 'error');
      return;
    }
    if (passphrase.length < MIN_PASSPHRASE) {
      showToast(`Recovery passphrase must be at least ${MIN_PASSPHRASE} characters.`, 'error');
      return;
    }
    setBusy(true);
    try {
      const key = await exportRecoveryKey(userId, passkey, passphrase);
      setRecoveryKey(key);
      setPasskey('');
      setPassphrase('');
      clearTimeout(clearTimer.current);
      clearTimer.current = setTimeout(() => setRecoveryKey(''), CLEAR_MS);
    } catch (e) {
      showToast(e.message || 'Failed to generate recovery key.', 'error');
    } finally {
      setBusy(false);
    }
  };

  const copyKey = () => {
    navigator.clipboard.writeText(recoveryKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Download the recovery blob as a small .kunji file. Web Share first (iOS Safari ignores
  // <a download> and opens inline; the share sheet routes to "Save to Files"), anchor fallback.
  const downloadKey = async () => {
    const file = new File([buildRecoveryEnvelope(recoveryKey)], recoveryFileName(new Date()), {
      type: 'application/octet-stream',
    });
    try {
      if (navigator.canShare?.({ files: [file] })) {
        await navigator.share({ files: [file] });
        return;
      }
    } catch {
      // user cancelled the share sheet, or share failed — fall through to the download anchor
    }
    const url = URL.createObjectURL(file);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Sheet onClose={onClose} z={60} labelledBy="recovery-title">
      <SheetHeading
        id="recovery-title"
        icon={KeyRound}
        info="A cold backup that restores your vault if you lose every device. Encrypted with a separate passphrase — store the key and passphrase apart."
      >
        Export recovery key
      </SheetHeading>
      {!recoveryKey ? (
        <div className="space-y-4">
          <PasswordField
            label="Current passkey"
            value={passkey}
            onChange={(e) => setPasskey(e.target.value)}
          />
          <div>
            <PasswordField
              label={`Recovery passphrase (min ${MIN_PASSPHRASE})`}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
            />
            {passphrase && (
              <div className="mt-2">
                <div className="h-1 rounded-full bg-line overflow-hidden">
                  <div
                    className={`h-full ${getStrength(passphrase).color} transition-all`}
                    style={{ width: getStrength(passphrase).width }}
                  />
                </div>
                <p className="text-[11px] text-muted mt-1">{getStrength(passphrase).label}</p>
              </div>
            )}
          </div>
          <div className="pt-1">
            <Btn variant="primary" onClick={handleGenerate} disabled={busy} className="w-full">
              {busy ? 'Generating…' : 'Generate recovery key'}
            </Btn>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex items-start gap-2 text-[13px] text-accent">
            <AlertTriangle size={15} className="mt-0.5 shrink-0" />
            <p>
              Save this now — the on-screen key clears in 60s. A downloaded file persists, so store it
              somewhere safe: anyone with the file <em>and</em> your recovery passphrase can restore
              your vault. Keep the two apart.
            </p>
          </div>
          <div className="flex items-start gap-3 border-y border-line py-3.5">
            <code className="flex-1 text-[12px] font-mono text-ink break-all leading-relaxed tabular">
              {recoveryKey}
            </code>
            <button
              onClick={copyKey}
              className="shrink-0 text-muted hover:text-ink transition-colors"
              title="Copy"
            >
              {copied ? (
                <CheckCircle2 size={15} className="text-success" />
              ) : (
                <Copy size={15} />
              )}
            </button>
          </div>
          <Btn variant="primary" onClick={downloadKey} className="w-full">
            <Download size={16} /> Download file
          </Btn>
          <Btn variant="quiet" onClick={onClose} className="w-full">
            Done
          </Btn>
        </div>
      )}
    </Sheet>
  );
};

export default RecoveryKeySheet;
