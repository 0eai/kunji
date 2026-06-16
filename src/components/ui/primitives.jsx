import React, { useEffect, useRef, useState } from 'react';
import { Eye, EyeOff, Info } from 'lucide-react';

/* Small quiet uppercase section label, optional trailing count. Editorial header. */
export const SectionLabel = ({ children, count, className = '' }) => (
  <div className={`flex items-baseline gap-2 ${className}`}>
    <span className="text-[11px] font-medium uppercase tracking-[0.16em] text-faint">
      {children}
    </span>
    {count != null && <span className="text-[11px] font-mono text-faint tabular">· {count}</span>}
  </div>
);

/* A sheet title block: optional leading accent icon + the <h2 id> (kept intact for the Sheet's
   aria-labelledby) + an optional (i) button that reveals `info` in a popover on tap — so the
   "what is this" intro is opt-in rather than always on screen. The popover anchors to the full
   title row (left-0 right-0) so it can't overflow the narrow sheet, and closes on outside tap or
   on toggling the icon. No Esc handler here on purpose: the Sheet already closes on Esc. */
export const SheetHeading = ({ id, icon: Icon, children, info, hintLabel = 'What is this?' }) => {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const panelId = `${id}-hint`;
  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('pointerdown', onDown);
    return () => document.removeEventListener('pointerdown', onDown);
  }, [open]);
  return (
    <div ref={ref} className="relative flex items-center gap-2.5 mb-3">
      {Icon && <Icon size={18} className="text-accent shrink-0" />}
      <h2 id={id} className="text-lg font-semibold tracking-tight">
        {children}
      </h2>
      {info && (
        <>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-label={hintLabel}
            title={hintLabel}
            aria-expanded={open}
            aria-controls={panelId}
            className={`p-1 -m-1 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
              open ? 'text-muted' : 'text-faint hover:text-muted'
            }`}
          >
            <Info size={15} strokeWidth={1.75} />
          </button>
          {open && (
            <p
              id={panelId}
              role="tooltip"
              className="absolute left-0 right-0 top-full mt-1 z-30 rounded-xl border border-line bg-surface shadow-md p-3 text-[13px] text-muted leading-relaxed animate-fade"
            >
              {info}
            </p>
          )}
        </>
      )}
    </div>
  );
};

/* Persistent field label — keeps context after the placeholder disappears on type. */
const FieldLabel = ({ children }) => (
  <span className="block text-[11px] uppercase tracking-[0.14em] text-faint mb-1.5">
    {children}
  </span>
);

const FIELD_BASE =
  'w-full bg-transparent border-0 border-b border-line rounded-none px-0 py-3 text-ink ' +
  'placeholder:text-faint outline-none transition-colors focus:border-accent';

/* Underline input — no box. Amber underline on focus. Optional label above. */
export const Field = React.forwardRef(({ className = '', mono = false, label, ...props }, ref) => {
  const input = (
    <input
      ref={ref}
      {...props}
      className={`${FIELD_BASE} ${mono ? 'font-mono tabular' : ''} ${className}`}
    />
  );
  if (!label) return input;
  return (
    <label className="block">
      <FieldLabel>{label}</FieldLabel>
      {input}
    </label>
  );
});
Field.displayName = 'Field';

/* Password underline input with a reveal toggle. */
export const PasswordField = React.forwardRef(({ className = '', label, ...props }, ref) => {
  const [show, setShow] = useState(false);
  const field = (
    <div className="relative">
      <input
        ref={ref}
        {...props}
        type={show ? 'text' : 'password'}
        className={`${FIELD_BASE} pr-9 ${className}`}
      />
      <button
        type="button"
        tabIndex={-1}
        onClick={() => setShow((s) => !s)}
        aria-label={show ? 'Hide passkey' : 'Show passkey'}
        className="absolute right-0 top-1/2 -translate-y-1/2 p-1 text-faint hover:text-muted transition-colors"
      >
        {show ? <EyeOff size={16} strokeWidth={1.75} /> : <Eye size={16} strokeWidth={1.75} />}
      </button>
    </div>
  );
  if (!label) return field;
  return (
    <div>
      <FieldLabel>{label}</FieldLabel>
      {field}
    </div>
  );
});
PasswordField.displayName = 'PasswordField';

/*
 * Button. variants:
 *  - primary : amber-fill pill, ink text
 *  - ghost   : transparent, accent text + icon
 *  - quiet   : transparent, muted text (secondary)
 *  - danger  : red text/outline
 */
const VARIANTS = {
  primary: 'bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full',
  ghost: 'text-accent hover:text-ink font-medium rounded-full',
  quiet: 'text-muted hover:text-ink font-medium rounded-full',
  danger: 'text-danger hover:bg-danger-soft font-semibold rounded-full',
};

export const Btn = ({ variant = 'primary', className = '', children, ...props }) => (
  <button
    {...props}
    className={`inline-flex items-center justify-center gap-2 px-5 py-3 text-sm
      transition-colors active:scale-[0.99] disabled:opacity-40 disabled:pointer-events-none
      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40
      ${VARIANTS[variant]} ${className}`}
  >
    {children}
  </button>
);

/* Inline spinner for in-button loading states. */
export const Spinner = ({ size = 16 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className="spin"
    aria-hidden="true"
  >
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
    <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
  </svg>
);

/* Deterministic hue from a string — stable color per app, no network request. */
const hueOf = (s = '') => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h % 360;
};

/* Monogram chip — first letter on a soft, app-deterministic colored tile. */
export const Monogram = ({ name = '?', seed, src, size = 'md' }) => {
  const dim =
    size === 'sm' ? 'w-8 h-8 text-sm' : size === 'lg' ? 'w-12 h-12 text-lg' : 'w-10 h-10 text-base';
  if (src) {
    return (
      <img
        src={src}
        alt=""
        className={`${dim} rounded-xl object-cover shrink-0`}
        onError={(e) => {
          e.currentTarget.style.display = 'none';
        }}
      />
    );
  }
  const h = hueOf(seed || name);
  return (
    <span
      className={`monogram ${dim} rounded-xl font-semibold flex items-center justify-center shrink-0 select-none`}
      style={{ '--mh': h }}
    >
      {(name || '?').trim().charAt(0).toUpperCase()}
    </span>
  );
};
