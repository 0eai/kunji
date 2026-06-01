import React, { useCallback, useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';

/* Ref-counted body scroll-lock so nested sheets don't fight over <body> overflow. */
let lockCount = 0;
let savedOverflow = '';

const SWIPE_CLOSE_PX = 80; // drag past this (or flick) to dismiss

/**
 * Bottom-sheet overlay (mobile) / centered panel (sm+). Replaces every centered
 * dialog card in the app. Hairline-bordered, warm-paper surface, slide-up motion +
 * animated dismiss. Easy to close on mobile: a pinned X, a swipe-down grabber,
 * backdrop tap, and Esc. Left-aligned content by default.
 *
 * @param {() => void} [onClose]  - called on X / scrim click / swipe / Esc (omit for non-dismissable)
 * @param {string} [labelledBy]   - id of the sheet's heading for a11y
 * @param {number} [z]            - z-index (default 50; nested sheets use 60/70)
 * @param {string} [className]    - extra classes on the sheet surface
 */
export default function Sheet({ children, onClose, labelledBy, z = 50, className = '' }) {
  const [closing, setClosing] = useState(false);
  const closingRef = useRef(false); // guard the timer without re-subscribing effects
  const closeTimer = useRef(null);

  // Swipe-to-dismiss (mobile): drag the grabber down to close.
  const [dragY, setDragY] = useState(0);
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef(null); // { y, t } or null while not dragging

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

  // Grabber drag handlers (no-op when non-dismissable). Starting the drag on the
  // grabber means it never competes with scrolling the sheet's content.
  const onGrabberDown = (e) => {
    if (!onClose) return;
    dragStart.current = { y: e.clientY, t: e.timeStamp };
    setDragging(true);
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };
  const onGrabberMove = (e) => {
    if (!dragStart.current) return;
    setDragY(Math.max(0, e.clientY - dragStart.current.y));
  };
  const onGrabberUp = (e) => {
    if (!dragStart.current) return;
    const dy = Math.max(0, e.clientY - dragStart.current.y);
    const dt = e.timeStamp - dragStart.current.t;
    const flick = dy > 24 && dt < 250; // quick downward flick
    dragStart.current = null;
    setDragging(false);
    if (dy > SWIPE_CLOSE_PX || flick) requestClose();
    else setDragY(0); // snap back (transition re-enabled below)
  };

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
        style={
          dragY
            ? { transform: `translateY(${dragY}px)`, transition: dragging ? 'none' : undefined }
            : undefined
        }
        className={`${closing ? 'animate-sheet-out' : 'animate-sheet'} relative flex flex-col bg-surface w-full sm:max-w-[26rem]
          rounded-t-[1.75rem] sm:rounded-[1.5rem] max-h-[92vh] overflow-hidden border-t sm:border border-line
          motion-safe:transition-transform ${className}`}
      >
        {/* Pinned close button — always reachable, even while content scrolls. */}
        {onClose && (
          <button
            onClick={requestClose}
            aria-label="Close"
            className="absolute right-3 top-3 sm:right-4 sm:top-4 z-20 p-2 rounded-full text-muted
              hover:text-ink hover:bg-line/60 active:bg-line transition-colors
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <X size={18} strokeWidth={2} />
          </button>
        )}

        {/* Scrollable content region (keeps the X pinned on the panel above). */}
        <div className="overflow-y-auto px-6 pt-3 pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:p-7">
          {/* grabber — mobile only; swipe it down to dismiss */}
          {onClose && (
            <div
              className="sm:hidden flex justify-center pb-3 -mt-1 -mx-6 pt-2 touch-none cursor-grab active:cursor-grabbing"
              onPointerDown={onGrabberDown}
              onPointerMove={onGrabberMove}
              onPointerUp={onGrabberUp}
              onPointerCancel={onGrabberUp}
            >
              <span className="h-1 w-9 rounded-full bg-line-strong" />
            </div>
          )}
          {!onClose && (
            <div className="sm:hidden flex justify-center pb-3">
              <span className="h-1 w-9 rounded-full bg-line-strong" />
            </div>
          )}
          {children}
        </div>
      </div>
    </div>
  );
}
