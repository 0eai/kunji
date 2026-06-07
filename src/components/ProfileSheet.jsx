import React from 'react';
import { UserCircle } from 'lucide-react';
import Sheet from './ui/Sheet';
import ProfileSettings from './ProfileSettings';

// Thin sheet wrapper around the self-contained ProfileSettings editor — mirrors the
// Link-a-device / Change-passkey sheet pattern. Closes via the X/backdrop, not on save.
const ProfileSheet = ({ userId, cryptoKey, onClose }) => (
  <Sheet onClose={onClose} z={60} labelledBy="profile-title">
    <div className="flex items-center gap-2.5 mb-3">
      <UserCircle size={18} className="text-accent" />
      <h2 id="profile-title" className="text-lg font-semibold tracking-tight">
        Profile
      </h2>
    </div>
    <ProfileSettings userId={userId} cryptoKey={cryptoKey} />
  </Sheet>
);

export default ProfileSheet;
