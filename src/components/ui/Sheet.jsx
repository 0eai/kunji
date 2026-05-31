import React, { useCallback, useEffect, useRef, useState } from 'react';

/* Ref-counted body scroll-lock so nested sheets don't fight over <body> overflow. */
let lockCount = 0;
let savedOverflow = '';

/**
 * Bottom-sheet overlay (mobile) / centered panel (sm+). Replaces every centered
 * dialog card in the app. Hairline-bordered, warm-paper surface, grabber handle
 * on mobile, slide-up motion + animated dismiss. Left-aligned content by default.
 *
 * @param {() => void} [onClose]  - called on scrim click / Esc (omit for non-dismissable)
 * @param {string} [labelledBy]   - id of the sheet's heading for a11y
 * @param {number} [z]            - z-index (default 50; nested sheets use 60/70)
 * @param {string} [className]    - extra classes on the sheet surface
 */
export default function Sheet({ children, onClose, labelledBy, z = 50, className = '' }) {
  const [closing, setClosing] = useState(false);
  const closingRef = useRef(false); // guard the timer without re-subscribing effects
  const closeTimer = useRef(null);

  useEffect(() => {
    if (lockCount === 0) {
      savedOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    }
    lockCount += 1;
    return () => {
      lockCount -= 1;
      if (lockCount === 0) document.body.style.overflow = savedOverflow;
    };
  }, []);

  // Play the exit animation, then unmount. Guarded by a ref so the keydown
  // effect below can stay subscribed to [onClose] only — putting `closing` in
  // its deps would tear down (clearTimeout) the pending close and strand an
  // invisible, click-blocking scrim on screen.
  const requestClose = useCallback(() => {
    if (!onClose || closingRef.current) return;
    closingRef.current = true;
    setClosing(true);
    closeTimer.current = setTimeout(onClose, 200);
  }, [onClose]);

  useEffect(() => {
    if (!onClose) return;
    const onKey = (e) => {
      if (e.key === 'Escape') requestClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, requestClose]);

  // Clear the pending timer only on real unmount.
  useEffect(() => () => clearTimeout(closeTimer.current), []);

  return (
    <div
      className={`fixed inset-0 flex items-end sm:items-center justify-center bg-scrim backdrop-blur-[2px] ${closing ? 'animate-fade-out pointer-events-none' : 'animate-fade'}`}
      style={{ zIndex: z }}
      onClick={requestClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        onClick={(e) => e.stopPropagation()}
        className={`${closing ? 'animate-sheet-out' : 'animate-sheet'} bg-surface w-full sm:max-w-[26rem] rounded-t-[1.75rem] sm:rounded-[1.5rem]
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
