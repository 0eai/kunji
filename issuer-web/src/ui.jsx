// kunji UI primitives — a subset of the wallet's src/components/ui/primitives.jsx (Btn, Spinner,
// SectionLabel), dependency-free so the issuer flow matches app.kunji.cc without importing the wallet.
export const SectionLabel = ({ children, className = '' }) => (
  <span className={`text-[11px] font-medium uppercase tracking-[0.16em] text-faint ${className}`}>{children}</span>
);

const VARIANTS = {
  primary: 'bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full',
  quiet: 'text-muted hover:text-ink font-medium rounded-full',
  danger: 'text-danger hover:bg-danger-soft font-semibold rounded-full',
};

export const Btn = ({ variant = 'primary', className = '', children, ...props }) => (
  <button
    {...props}
    className={`inline-flex items-center justify-center gap-2 px-5 py-3 text-sm transition-colors active:scale-[0.99] disabled:opacity-40 disabled:pointer-events-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${VARIANTS[variant]} ${className}`}
  >
    {children}
  </button>
);

export const Spinner = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="spin" aria-hidden="true">
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
    <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
  </svg>
);
