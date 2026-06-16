import React from 'react';
import { UserCircle } from 'lucide-react';
import Sheet from './ui/Sheet';
import { SheetHeading } from './ui/primitives';
import ProfileSettings from './ProfileSettings';

// Thin sheet wrapper around the self-contained ProfileSettings editor — mirrors the
// Link-a-device / Change-passkey sheet pattern. Closes via the X/backdrop, not on save.
const ProfileSheet = ({ userId, cryptoKey, onClose }) => (
  <Sheet onClose={onClose} z={60} labelledBy="profile-title">
    <SheetHeading
      id="profile-title"
      icon={UserCircle}
      info="Optional. By default each app sees a random, unlinkable name and icon. Set a name or photo here and you can choose — per app, when it asks — to share it instead. It's never verified and never sent without your consent."
    >
      Profile
    </SheetHeading>
    <ProfileSettings userId={userId} cryptoKey={cryptoKey} />
  </Sheet>
);

export default ProfileSheet;
