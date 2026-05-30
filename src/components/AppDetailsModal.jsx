import React, { useState, useEffect } from 'react';
import {
  X, Copy, CheckCircle2, Fingerprint, Globe, Activity, Link as LinkIcon,
  ShieldCheck, Unlink, Circle,
} from 'lucide-react';
import { deriveSubFromPublicKey } from '../services/identity';
import { listenToActivityLog } from '../services/activityLog';

const ACTIVITY_ICONS = { ShieldCheck, Link: LinkIcon, Unlink };
const TYPE_COLOR = { success: 'text-green-400', danger: 'text-red-400', info: 'text-gray-400' };

const relTime = (createdAt) => {
  const ms = createdAt?.toMillis ? createdAt.toMillis() : (createdAt?.seconds ? createdAt.seconds * 1000 : null);
  if (!ms) return '';
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

const AppDetailsModal = ({ app, userId, cryptoKey, onClose }) => {
  const [sub, setSub] = useState('');
  const [copiedSub, setCopiedSub] = useState(false);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    if (!app?.publicKey) return;
    deriveSubFromPublicKey(app.publicKey).then(setSub).catch(() => setSub(''));
  }, [app?.publicKey]);

  // This device's recent activity for this app (tagged with its domain).
  useEffect(() => {
    if (!userId) return;
    const unsub = listenToActivityLog(userId, (all) => {
      setEvents(all.filter((e) => e.domain === app.domain).slice(0, 8));
    }, 50, cryptoKey);
    return unsub;
  }, [userId, cryptoKey, app.domain]);

  const copySub = () => { navigator.clipboard.writeText(sub); setCopiedSub(true); setTimeout(() => setCopiedSub(false), 2000); };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#18181b] border border-[#27272a] rounded-3xl w-full max-w-sm p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-start justify-between mb-5">
          <div className="flex items-center gap-3 min-w-0">
            {app?.iconUrl ? (
              <img src={app.iconUrl} alt="" className="w-10 h-10 rounded-xl object-cover flex-shrink-0" onError={(e) => { e.target.style.display = 'none'; }} />
            ) : (
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center flex-shrink-0">
                <LinkIcon size={18} className="text-white" />
              </div>
            )}
            <div className="min-w-0">
              <h2 className="text-lg font-bold text-white truncate">{app?.name}</h2>
              <p className="text-xs text-gray-500 flex items-center gap-1 truncate"><Globe size={11} /> {app?.domain}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-[#27272a] transition-colors flex-shrink-0">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-5">
          {/* Per-app subject ID */}
          {sub && (
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1 flex items-center gap-1">
                <Fingerprint size={12} /> Your ID for this app
              </p>
              <div className="relative">
                <code className="w-full p-2.5 pr-10 text-xs font-mono bg-black border border-[#27272a] rounded-xl text-gray-300 break-all block">
                  {sub}
                </code>
                <button onClick={copySub} className="absolute top-2 right-2 p-1.5 rounded-lg hover:bg-[#27272a] transition-colors" title="Copy ID">
                  {copiedSub ? <CheckCircle2 size={14} className="text-green-400" /> : <Copy size={14} className="text-gray-500" />}
                </button>
              </div>
              <p className="text-[11px] text-gray-600 mt-1.5 leading-relaxed">
                The stable identifier this app sees for you — unique to it, so apps can't link your accounts.
              </p>
            </div>
          )}

          {/* Recent activity for this app */}
          <div>
            <p className="text-xs font-medium text-gray-500 mb-2 flex items-center gap-1">
              <Activity size={12} /> Recent activity
            </p>
            {events.length === 0 ? (
              <p className="text-xs text-gray-600">No activity for this app on this device yet.</p>
            ) : (
              <div className="space-y-2">
                {events.map((e) => {
                  const Icon = ACTIVITY_ICONS[e.icon] || Circle;
                  return (
                    <div key={e.id} className="flex items-center gap-3">
                      <Icon size={14} className={`${TYPE_COLOR[e.type] || 'text-gray-400'} flex-shrink-0`} />
                      <span className="text-xs text-gray-300 flex-1 truncate">{e.action}</span>
                      <span className="text-[10px] text-gray-600 flex-shrink-0">{relTime(e.createdAt)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <button onClick={onClose} className="w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors">
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

export default AppDetailsModal;
