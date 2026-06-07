import React, { useState } from 'react';
import { Lock } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn, PasswordField } from './ui/primitives';
import { changePasskey } from '../services/vault';
import { getStrength, MIN_PASSKEY_LENGTH } from '../lib/passkeyStrength';
import { logActivity } from '../services/activityLog';
import { useToast } from '../contexts/ToastContext';

// Re-auth with the current passkey, then re-wrap the (already-unlocked) master key under a new one.
// Only THIS device's local wrap changes — the master key, vaultId, recovery key, and other linked
// devices are untouched. Mirrors the IssueLinkSheet/AuthorizeAgentSheet sheet pattern.
const ChangePasskeySheet = ({ userId, masterKey, onClose }) => {
  const { showToast } = useToast();
  const [curKey, setCurKey] = useState('');
  const [newKey, setNewKey] = useState('');
  const [newKey2, setNewKey2] = useState('');
  const [changing, setChanging] = useState(false);

  const handleChangePasskey = async () => {
    if (newKey.length < MIN_PASSKEY_LENGTH) {
      showToast(`New passkey must be at least ${MIN_PASSKEY_LENGTH} characters.`, 'error');
      return;
    }
    if (getStrength(newKey).label === 'Weak') {
      showToast('Choose a stronger passkey.', 'error');
      return;
    }
    if (newKey !== newKey2) {
      showToast('New passkeys do not match.', 'error');
      return;
    }
    setChanging(true);
    try {
      await changePasskey(userId, masterKey, curKey, newKey);
      logActivity(userId, 'Passkey changed', 'success', 'Lock', masterKey);
      showToast('Passkey updated.');
      onClose();
    } catch (e) {
      showToast(e.message || 'Could not change passkey.', 'error');
    } finally {
      setChanging(false);
    }
  };

  return (
    <Sheet onClose={() => !changing && onClose()} z={60} labelledBy="changekey-title">
      <div className="flex items-center gap-2.5 mb-3">
        <Lock size={18} className="text-accent" />
        <h2 id="changekey-title" className="text-lg font-semibold tracking-tight">
          Change passkey
        </h2>
      </div>
      <p className="text-[14px] text-muted leading-relaxed mb-5">
        Set a new passkey for this device. Your recovery key and any other linked devices keep their
        own passkeys — only this device changes.
      </p>
      <div className="space-y-4">
        <PasswordField
          label="Current passkey"
          value={curKey}
          onChange={(e) => setCurKey(e.target.value)}
        />
        <div>
          <PasswordField
            label={`New passkey (min ${MIN_PASSKEY_LENGTH})`}
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
          />
          {newKey && (
            <div className="mt-2">
              <div className="h-1 rounded-full bg-line overflow-hidden">
                <div
                  className={`h-full ${getStrength(newKey).color} transition-all`}
                  style={{ width: getStrength(newKey).width }}
                />
              </div>
              <p className="text-[11px] text-muted mt-1">{getStrength(newKey).label}</p>
            </div>
          )}
        </div>
        <PasswordField
          label="Confirm new passkey"
          value={newKey2}
          onChange={(e) => setNewKey2(e.target.value)}
        />
        <div className="flex items-center justify-end gap-1 pt-1">
          <Btn variant="quiet" onClick={() => !changing && onClose()} disabled={changing}>
            Cancel
          </Btn>
          <Btn
            variant="primary"
            onClick={handleChangePasskey}
            disabled={changing || !curKey || !newKey || !newKey2}
          >
            {changing ? 'Updating…' : 'Update passkey'}
          </Btn>
        </div>
      </div>
    </Sheet>
  );
};

export default ChangePasskeySheet;
