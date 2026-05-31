import React, { useState } from 'react';
import { Download, Share, Plus } from 'lucide-react';
import { useInstall } from '../hooks/useInstall';
import Sheet from './ui/Sheet';

/**
 * "Install kunji" affordance. Hidden once installed (standalone). On Chrome it
 * triggers the native prompt; on iOS Safari it shows Add-to-Home-Screen steps.
 * @param {'block'|'row'} variant - lock-screen text link, or a hairline list row (panel)
 */
const InstallButton = ({ variant = 'block' }) => {
  const { isStandalone, isIOS, canPrompt, promptInstall } = useInstall();
  const [showIOS, setShowIOS] = useState(false);

  if (isStandalone) return null;
  if (!canPrompt && !isIOS) return null; // browser can't install (e.g. desktop Safari/Firefox)

  const onClick = () => {
    if (canPrompt) promptInstall();
    else setShowIOS(true);
  };

  const trigger =
    variant === 'row' ? (
      <button
        onClick={onClick}
        className="w-full flex items-center gap-3 py-4 px-3 -mx-3 rounded-xl text-left text-ink hover:bg-line/40 active:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
      >
        <Download size={17} strokeWidth={1.75} className="text-muted" />{' '}
        <span className="text-[15px] font-medium">Install kunji</span>
      </button>
    ) : (
      <button
        onClick={onClick}
        className="w-full inline-flex items-center justify-center gap-2 text-sm font-medium text-accent hover:text-ink transition-colors"
      >
        <Download size={16} /> Install kunji
      </button>
    );

  return (
    <>
      {trigger}
      {showIOS && (
        <Sheet onClose={() => setShowIOS(false)} z={70} labelledBy="install-title">
          <h2 id="install-title" className="text-lg font-semibold tracking-tight mb-1">
            Install kunji
          </h2>
          <p className="text-[14px] text-muted mb-6">
            Add kunji to your home screen for an app-like experience.
          </p>
          <ol className="divide-y divide-line border-y border-line">
            <li className="flex items-center gap-3 py-4 text-[15px] text-ink">
              <span className="w-6 h-6 rounded-full bg-accent-soft text-accent text-xs font-semibold flex items-center justify-center shrink-0">
                1
              </span>
              <span>
                Tap the <Share size={15} className="text-accent inline-block align-text-bottom" />{' '}
                <strong className="font-medium">Share</strong> icon in Safari.
              </span>
            </li>
            <li className="flex items-center gap-3 py-4 text-[15px] text-ink">
              <span className="w-6 h-6 rounded-full bg-accent-soft text-accent text-xs font-semibold flex items-center justify-center shrink-0">
                2
              </span>
              <span>
                Choose <Plus size={15} className="text-accent inline-block align-text-bottom" />{' '}
                <strong className="font-medium">Add to Home Screen</strong>.
              </span>
            </li>
          </ol>
        </Sheet>
      )}
    </>
  );
};

export default InstallButton;
