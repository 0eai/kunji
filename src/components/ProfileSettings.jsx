import React, { useState, useEffect } from 'react';
import { Upload, Trash2 } from 'lucide-react';
import { deriveVaultId } from '../lib/crypto';
import { loadProfile, saveProfile } from '../services/profile';
import { Field, Btn, Monogram } from './ui/primitives';
import { useToast } from '../contexts/ToastContext';

// Downscale a picked image to a small square WebP data-URI so it fits the encrypted
// profile doc (and never leaves the device un-encrypted).
const AVATAR_PX = 128;
const resizeToDataUri = (file) =>
  new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = AVATAR_PX;
      const ctx = canvas.getContext('2d');
      const scale = Math.max(AVATAR_PX / img.width, AVATAR_PX / img.height);
      const w = img.width * scale;
      const h = img.height * scale;
      ctx.drawImage(img, (AVATAR_PX - w) / 2, (AVATAR_PX - h) / 2, w, h);
      URL.revokeObjectURL(url);
      let out = canvas.toDataURL('image/webp', 0.8);
      if (out.length > 40000) out = canvas.toDataURL('image/webp', 0.55); // keep doc small
      resolve(out);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('bad_image'));
    };
    img.src = url;
  });

// Optional custom profile (Layer 2). Off by default for everyone — kunji's per-app
// default identity (name + identicon) needs nothing here. When set, the user may choose,
// per login, to share it with an app that asks. It is self-asserted, never verified.
const ProfileSettings = ({ userId, cryptoKey }) => {
  const { showToast } = useToast();
  const [vaultId, setVaultId] = useState(null);
  const [displayName, setDisplayName] = useState('');
  const [avatar, setAvatar] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let alive = true;
    deriveVaultId(cryptoKey).then(async (vid) => {
      if (!alive) return;
      setVaultId(vid);
      const p = await loadProfile(vid, cryptoKey);
      if (!alive) return;
      if (p) {
        setDisplayName(p.displayName);
        setAvatar(p.avatar);
      }
      setLoaded(true);
    });
    return () => {
      alive = false;
    };
  }, [cryptoKey]);

  const onPick = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (!file.type.startsWith('image/') || file.size > 8 * 1024 * 1024) {
      showToast('Pick an image under 8 MB.', 'error');
      return;
    }
    try {
      setAvatar(await resizeToDataUri(file));
    } catch {
      showToast("Couldn't read that image.", 'error');
    }
  };

  const onSave = async () => {
    if (!vaultId) return;
    setSaving(true);
    try {
      const clean = await saveProfile(vaultId, cryptoKey, { displayName, avatar }, userId);
      setDisplayName(clean.displayName);
      setAvatar(clean.avatar);
      showToast(clean.displayName || clean.avatar ? 'Profile saved.' : 'Profile cleared.');
    } catch (e) {
      showToast('Save failed: ' + e.message, 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <p className="text-[13px] text-muted leading-relaxed mb-4">
        Optional. By default each app sees a random, unlinkable name and icon. Set a name or photo
        here and you can choose — per app, when it asks — to share it instead. It's never verified
        and never sent without your consent.
      </p>

      <div className="flex items-center gap-4 mb-4">
        {avatar ? (
          <img
            src={avatar}
            alt=""
            className="w-12 h-12 rounded-xl border border-line object-cover shrink-0"
          />
        ) : (
          <Monogram name={displayName || '?'} size="lg" />
        )}
        <div className="flex items-center gap-1">
          <label className="inline-flex items-center gap-1.5 text-[13px] font-medium text-accent hover:text-ink cursor-pointer transition-colors">
            <Upload size={15} /> {avatar ? 'Replace' : 'Add photo'}
            <input type="file" accept="image/*" className="hidden" onChange={onPick} />
          </label>
          {avatar && (
            <button
              onClick={() => setAvatar('')}
              className="inline-flex items-center gap-1.5 text-[13px] font-medium text-muted hover:text-danger px-2 transition-colors"
            >
              <Trash2 size={15} /> Remove
            </button>
          )}
        </div>
      </div>

      <Field
        value={displayName}
        onChange={(e) => setDisplayName(e.target.value)}
        placeholder="Display name"
        maxLength={60}
        className="mb-4"
      />

      <Btn variant="primary" onClick={onSave} disabled={!loaded || saving} className="w-full">
        {saving ? 'Saving…' : 'Save profile'}
      </Btn>
    </div>
  );
};

export default ProfileSettings;
