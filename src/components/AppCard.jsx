import React from 'react';
import { Globe, Calendar, Link, Info, Trash2 } from 'lucide-react';

const AppCard = ({ app, onDetails, onDelete }) => {
  const createdDate = app.createdAt?.toDate
    ? app.createdAt.toDate().toLocaleDateString()
    : app.createdAt ? new Date(app.createdAt).toLocaleDateString() : null;

  return (
    <div className="bg-[#18181b] border border-[#27272a] rounded-2xl p-4 flex items-center gap-4 group hover:border-[#3f3f46] transition-all">
      {app.iconUrl ? (
        <img src={app.iconUrl} alt={app.name} className="w-12 h-12 rounded-xl object-cover flex-shrink-0"
          onError={(e) => { e.target.style.display = 'none'; }} />
      ) : (
        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center flex-shrink-0">
          <Link size={22} className="text-white" />
        </div>
      )}

      <div className="flex-1 min-w-0">
        <p className="font-semibold text-white truncate">{app.name}</p>
        <div className="flex items-center gap-1 text-sm text-gray-500 mt-0.5">
          <Globe size={12} />
          <span className="truncate">{app.domain}</span>
        </div>
        {createdDate && (
          <div className="flex items-center gap-1 text-xs text-gray-600 mt-0.5">
            <Calendar size={11} />
            <span>{createdDate}</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-1 opacity-100 md:opacity-0 md:group-hover:opacity-100 transition-opacity">
        <button onClick={onDetails} className="p-2 text-gray-500 hover:text-amber-400 hover:bg-amber-950/50 rounded-lg transition-colors" title="View public key">
          <Info size={16} />
        </button>
        <button onClick={onDelete} className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-950/50 rounded-lg transition-colors" title="Remove app">
          <Trash2 size={16} />
        </button>
      </div>
    </div>
  );
};

export default AppCard;
