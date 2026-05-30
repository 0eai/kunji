import React from 'react';

/* Small quiet uppercase section label, optional trailing count. Editorial header. */
export const SectionLabel = ({ children, count, className = '' }) => (
  <div className={`flex items-baseline gap-2 ${className}`}>
    <span className="text-[11px] font-medium uppercase tracking-[0.16em] text-faint">{children}</span>
    {count != null && <span className="text-[11px] font-mono text-faint">· {count}</span>}
  </div>
);

/* Underline input — no box. Amber underline on focus. */
export const Field = React.forwardRef(({ className = '', mono = false, ...props }, ref) => (
  <input
    ref={ref}
    {...props}
    className={`w-full bg-transparent border-0 border-b border-line rounded-none px-0 py-3 text-ink
      placeholder:text-faint outline-none transition-colors
      focus:border-accent focus:ring-0 ${mono ? 'font-mono' : ''} ${className}`}
  />
));
Field.displayName = 'Field';

/*
 * Button. variants:
 *  - primary : amber-fill pill, ink text
 *  - ghost   : transparent, accent text + icon
 *  - quiet   : transparent, muted text (secondary)
 *  - danger  : red text/outline
 */
const VARIANTS = {
  primary: 'bg-accent-fill hover:bg-accent text-ink font-semibold rounded-full',
  ghost:   'text-accent hover:text-ink font-medium rounded-full',
  quiet:   'text-muted hover:text-ink font-medium rounded-full',
  danger:  'text-danger hover:bg-danger-soft font-semibold rounded-full',
};

export const Btn = ({ variant = 'primary', className = '', children, ...props }) => (
  <button
    {...props}
    className={`inline-flex items-center justify-center gap-2 px-5 py-3 text-sm
      transition-colors active:scale-[0.99] disabled:opacity-40 disabled:pointer-events-none
      ${VARIANTS[variant]} ${className}`}
  >
    {children}
  </button>
);

/* Monogram chip — first letter of an app name on a soft amber tile. */
export const Monogram = ({ name = '?', src, size = 'md' }) => {
  const dim = size === 'sm' ? 'w-8 h-8 text-sm' : size === 'lg' ? 'w-12 h-12 text-lg' : 'w-10 h-10 text-base';
  if (src) {
    return <img src={src} alt="" className={`${dim} rounded-xl object-cover shrink-0`} onError={(e) => { e.currentTarget.style.display = 'none'; }} />;
  }
  return (
    <span className={`${dim} rounded-xl bg-accent-soft text-accent font-semibold flex items-center justify-center shrink-0 select-none`}>
      {(name || '?').trim().charAt(0).toUpperCase()}
    </span>
  );
};
