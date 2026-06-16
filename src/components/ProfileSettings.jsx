import React, { useState, useEffect } from 'react';
import { Upload, Trash2 } from 'lucide-react';
import { deriveVaultId } from '../lib/crypto';
import { loadProfile, saveProfile } from '../services/profile';
import { Field, Btn, Monogram } from './ui/primitives';
import { useToast } from '../contexts/ToastContext';

// Downscale + center-crop a picked image to a small 96px square data-URI so it fits
// the encrypted profile doc (and never leaves the device un-encrypted). Re-encoding via
// canvas also strips EXIF/metadata.
const AVATAR_PX = 96;
const TARGET_BYTES = 24 * 1024; // keep well under the function's 64 KB profile cap

// Encode the canvas, preferring WebP but falling back to JPEG where the browser can't
// encode WebP (older Safari silently returns a big PNG otherwise), then step quality
// down until under the byte target. Returns the smallest data-URI produced.
const compressCanvas = (canvas) => {
  const webpOk = canvas.toDataURL('image/webp', 0.7).startsWith('data:image/webp');
  const type = webpOk ? 'image/webp' : 'image/jpeg';
  let best = canvas.toDataURL(type, 0.82);
  for (let q = 0.82; q >= 0.4 && best.length > TARGET_BYTES; q -= 0.12) {
    const next = canvas.toDataURL(type, q);
    if (next.length < best.length) best = next;
  }
  return best;
};

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
      resolve(compressCanvas(canvas));
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
  const [shareByDefault, setShareByDefault] = useState(false);
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
        setShareByDefault(p.shareByDefault);
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
      const clean = await saveProfile(
        vaultId,
        cryptoKey,
        { displayName, avatar, shareByDefault },
        userId,
      );
      setDisplayName(clean.displayName);
      setAvatar(clean.avatar);
      setShareByDefault(clean.shareByDefault);
      showToast(clean.displayName || clean.avatar ? 'Profile saved.' : 'Profile cleared.');
    } catch (e) {
      showToast('Save failed: ' + e.message, 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
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

      {/* Default-share preference: only meaningful once a name/photo is set. Sets the STARTING
          position of the per-login "Share your profile" toggle — the user can still turn it off. */}
      <button
        type="button"
        onClick={() => setShareByDefault((v) => !v)}
        aria-pressed={shareByDefault}
        disabled={!displayName && !avatar}
        className="w-full flex items-center gap-3 text-left mb-4 rounded-xl border border-line p-3.5 hover:bg-line/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <span className="min-w-0 flex-1">
          <span className="block text-[13px] font-medium text-ink">Share my profile by default</span>
          <span className="block text-[12px] text-muted">
            {!displayName && !avatar
              ? 'Set a name or photo first.'
              : "When an app asks, start with it shared — you can still turn it off per app."}
          </span>
        </span>
        <span
          className={`shrink-0 w-9 h-5 rounded-full p-0.5 transition-colors ${
            shareByDefault ? 'bg-accent-fill' : 'bg-line'
          }`}
        >
          <span
            className={`block w-4 h-4 rounded-full bg-white transition-transform ${
              shareByDefault ? 'translate-x-4' : ''
            }`}
          />
        </span>
      </button>

      <Btn variant="primary" onClick={onSave} disabled={!loaded || saving} className="w-full">
        {saving ? 'Saving…' : 'Save profile'}
      </Btn>
    </div>
  );
};

export default ProfileSettings;
