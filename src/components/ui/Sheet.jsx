import React, { useEffect } from 'react';

/**
 * Bottom-sheet overlay (mobile) / centered panel (sm+). Replaces every centered
 * dialog card in the app. Hairline-bordered, warm-paper surface, grabber handle
 * on mobile, slide-up motion. Left-aligned content by default.
 *
 * @param {() => void} [onClose]  - called on scrim click / Esc (omit for non-dismissable)
 * @param {string} [labelledBy]   - id of the sheet's heading for a11y
 * @param {number} [z]            - z-index (default 50; nested sheets use 60/70)
 * @param {string} [className]    - extra classes on the sheet surface
 */
export default function Sheet({ children, onClose, labelledBy, z = 50, className = '' }) {
  useEffect(() => {
    if (!onClose) return;
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 flex items-end sm:items-center justify-center bg-ink/25 backdrop-blur-[2px] animate-fade"
      style={{ zIndex: z }}
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        onClick={(e) => e.stopPropagation()}
        className={`animate-sheet bg-surface w-full sm:max-w-[26rem] rounded-t-[1.75rem] sm:rounded-[1.5rem]
          max-h-[92vh] overflow-y-auto border-t sm:border border-line
          px-6 pt-3 pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:p-7 ${className}`}
      >
        {/* grabber — mobile only */}
        <div className="sm:hidden flex justify-center pb-3">
          <span className="h-1 w-9 rounded-full bg-line-strong" />
        </div>
        {children}
      </div>
    </div>
  );
}
