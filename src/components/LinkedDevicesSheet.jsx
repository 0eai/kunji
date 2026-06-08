import React, { useState, useEffect, useCallback } from 'react';
import { Smartphone } from 'lucide-react';
import Sheet from './ui/Sheet';
import { Btn } from './ui/primitives';
import { listDevices, thisDeviceId } from '../services/devices';
import { relTime } from '../lib/activityFormat';
import IssueLinkSheet from './IssueLinkSheet';

// Devices linked to this identity (shared, encrypted). Awareness-only — there's no remote unlink
// (that would re-key the whole identity); to remove one, sign out on that device. Mirrors the
// AgentsSheet pattern: a list + an "Add a device" button that opens the existing issuer flow.
const LinkedDevicesSheet = ({ userId, masterKey, onClose }) => {
  const [devices, setDevices] = useState(null); // null = loading
  const [showIssue, setShowIssue] = useState(false);
  const me = thisDeviceId();

  const refresh = useCallback(() => {
    listDevices(masterKey)
      .then(setDevices)
      .catch(() => setDevices([]));
  }, [masterKey]);

  useEffect(() => refresh(), [refresh]);

  return (
    <Sheet onClose={onClose} z={60} labelledBy="devices-title">
      <div className="flex items-center gap-2.5 mb-3">
        <Smartphone size={18} className="text-accent" />
        <h2 id="devices-title" className="text-lg font-semibold tracking-tight">
          Linked devices
        </h2>
      </div>
      <p className="text-[14px] text-muted leading-relaxed mb-5">
        Devices that hold this identity. To remove one, sign out on that device — it can't be unlinked
        remotely (that would re-key your whole identity).
      </p>

      {devices === null ? (
        <p className="text-[13px] text-faint mb-5">Loading…</p>
      ) : devices.length === 0 ? (
        <p className="text-[13px] text-faint mb-5">No devices recorded yet.</p>
      ) : (
        <div className="divide-y divide-line border-y border-line mb-5">
          {devices.map((d) => (
            <div key={d.id} className="flex items-center gap-3 py-3">
              <Smartphone size={16} className="text-muted shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-[14px] text-ink truncate">{d.label}</p>
                <p className="text-[11px] text-faint truncate">
                  linked {relTime({ seconds: d.createdAt })}
                </p>
              </div>
              {d.id === me && (
                <span className="shrink-0 text-[11px] font-medium text-accent border border-accent/40 rounded-full px-2 py-0.5">
                  This device
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      <Btn variant="primary" onClick={() => setShowIssue(true)} className="w-full">
        <Smartphone size={16} /> Add a device
      </Btn>

      {showIssue && (
        <IssueLinkSheet
          masterKey={masterKey}
          userId={userId}
          onClose={() => {
            setShowIssue(false);
            refresh(); // the new device records itself on its first unlock; refresh opportunistically
          }}
        />
      )}
    </Sheet>
  );
};

export default LinkedDevicesSheet;
