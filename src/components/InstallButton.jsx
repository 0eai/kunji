import React, { useState } from 'react';
import { Download, Share, Plus, X } from 'lucide-react';
import { useInstall } from '../hooks/useInstall';

/**
 * "Install kunji" affordance. Hidden once installed (standalone). On Chrome it
 * triggers the native prompt; on iOS Safari it shows Add-to-Home-Screen steps.
 * @param {'block'|'row'} variant - full-width button (lock screen) or compact row (panel)
 */
const InstallButton = ({ variant = 'block' }) => {
  const { isStandalone, isIOS, canPrompt, promptInstall } = useInstall();
  const [showIOS, setShowIOS] = useState(false);

  if (isStandalone) return null;
  if (!canPrompt && !isIOS) return null; // browser can't install (e.g. desktop Safari/Firefox)

  const onClick = () => { if (canPrompt) promptInstall(); else setShowIOS(true); };

  const btnClass = variant === 'row'
    ? 'w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-[#eef0f2] hover:bg-[#e2e5e9] text-[#18181b] font-semibold transition-colors'
    : 'w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-[#eef0f2] hover:bg-[#e2e5e9] text-[#18181b] text-sm font-semibold transition-colors';

  return (
    <>
      <button onClick={onClick} className={btnClass}>
        <Download size={16} /> Install kunji
      </button>

      {showIOS && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4" onClick={() => setShowIOS(false)}>
          <div className="bg-white border border-[#e6e8eb] rounded-3xl w-full max-w-sm p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-[#18181b]">Install kunji</h2>
              <button onClick={() => setShowIOS(false)} className="p-1.5 rounded-lg text-gray-500 hover:text-[#18181b] hover:bg-[#eef0f2] transition-colors">
                <X size={18} />
              </button>
            </div>
            <p className="text-sm text-gray-600 mb-4">Add kunji to your home screen for an app-like experience:</p>
            <ol className="space-y-3 text-sm text-gray-700">
              <li className="flex items-center gap-3">
                <span className="w-6 h-6 rounded-full bg-amber-500 text-black text-xs font-bold flex items-center justify-center flex-shrink-0">1</span>
                Tap the <Share size={15} className="text-amber-600 inline-block" /> <strong>Share</strong> icon in Safari.
              </li>
              <li className="flex items-center gap-3">
                <span className="w-6 h-6 rounded-full bg-amber-500 text-black text-xs font-bold flex items-center justify-center flex-shrink-0">2</span>
                Choose <Plus size={15} className="text-amber-600 inline-block" /> <strong>Add to Home Screen</strong>.
              </li>
            </ol>
          </div>
        </div>
      )}
    </>
  );
};

export default InstallButton;
