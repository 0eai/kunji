// kunji UI primitives for the operator console — a superset of the wallet's shared look (Btn, Spinner,
// SectionLabel, Field) plus console pieces (Modal, ConfirmDialog, StatCard, Badge, Skeleton, EmptyState,
// Sparkline, BarChart). Dependency-free (inline SVG; no icon/chart libs) so the admin bundle stays minimal.
import { useEffect, useRef } from 'react';

export const SectionLabel = ({ children, count, className = '' }) => (
  <div className={`flex items-baseline gap-2 ${className}`}>
    <span className="text-[11px] font-medium uppercase tracking-[0.16em] text-faint">{children}</span>
    {count != null && <span className="text-[11px] font-mono text-faint tabular">· {count}</span>}
  </div>
);

const VARIANTS = {
  primary: 'bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full',
  quiet: 'text-muted hover:text-ink font-medium rounded-full',
  danger: 'text-danger hover:bg-danger-soft font-semibold rounded-full',
  outline: 'border border-line hover:border-line-strong text-ink font-medium rounded-full',
};

export const Btn = ({ variant = 'primary', className = '', children, ...props }) => (
  <button
    {...props}
    className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 text-sm transition-colors active:scale-[0.99] disabled:opacity-40 disabled:pointer-events-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${VARIANTS[variant]} ${className}`}
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

export const Field = ({ label, className = '', ...props }) => (
  <label className="block">
    {label && <span className="block text-[11px] uppercase tracking-[0.14em] text-faint mb-1.5">{label}</span>}
    <input
      {...props}
      className={`w-full bg-transparent border-0 border-b border-line rounded-none px-0 py-2.5 text-ink placeholder:text-faint outline-none transition-colors focus:border-accent ${className}`}
    />
  </label>
);

// A small inline X (avoids pulling in an icon library for the one glyph the console needs).
export const XIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
  </svg>
);

export const Card = ({ children, className = '' }) => (
  <div className={`rounded-2xl border border-line bg-surface ${className}`}>{children}</div>
);

export const Badge = ({ tone = 'muted', children }) => {
  const tones = { success: 'text-success', danger: 'text-danger', warning: 'text-accent', muted: 'text-faint' };
  return <span className={`text-[12px] ${tones[tone] || tones.muted}`}>{children}</span>;
};

// Big-number stat tile.
export const StatCard = ({ label, value, hint, tone }) => (
  <Card className="px-4 py-3.5">
    <div className={`text-[1.6rem] font-semibold tabular leading-none ${tone === 'danger' ? 'text-danger' : ''}`}>
      {value}
    </div>
    <div className="text-[12px] text-faint mt-1.5">{label}</div>
    {hint != null && <div className="text-[11px] text-muted mt-0.5">{hint}</div>}
  </Card>
);

export const Skeleton = ({ className = '' }) => <div className={`animate-pulse rounded-md bg-line/70 ${className}`} />;

// A few stacked skeleton rows for a loading list/table.
export const SkeletonRows = ({ rows = 4 }) => (
  <div className="space-y-2 mt-3">
    {Array.from({ length: rows }).map((_, i) => (
      <Skeleton key={i} className="h-12 w-full" />
    ))}
  </div>
);

export const EmptyState = ({ title, children }) => (
  <div className="text-center py-12 px-6">
    <p className="text-[15px] font-medium text-ink">{title}</p>
    {children && <p className="text-[13px] text-muted mt-1.5 max-w-sm mx-auto leading-relaxed">{children}</p>}
  </div>
);

// Centered modal (scrim + card). Esc / scrim-click / X close it; focus moves to the dialog on open.
export const Modal = ({ children, onClose, labelledBy, size = 'sm' }) => {
  const ref = useRef(null);
  useEffect(() => {
    ref.current?.focus();
    const onKey = (e) => e.key === 'Escape' && onClose?.();
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);
  const widths = { sm: 'sm:max-w-md', lg: 'sm:max-w-2xl', xl: 'sm:max-w-4xl' };
  return (
    <div
      className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center bg-scrim backdrop-blur-[2px] animate-fade p-0 sm:p-6"
      onClick={onClose}
    >
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        onClick={(e) => e.stopPropagation()}
        className={`animate-rise relative w-full ${widths[size]} max-h-[92vh] overflow-y-auto bg-surface border border-line rounded-t-2xl sm:rounded-2xl p-6 outline-none`}
      >
        {onClose && (
          <button
            onClick={onClose}
            aria-label="Close"
            className="absolute right-3 top-3 p-2 rounded-full text-muted hover:text-ink hover:bg-line/60 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <XIcon />
          </button>
        )}
        {children}
      </div>
    </div>
  );
};

export const ConfirmDialog = ({ title, body, confirmLabel = 'Confirm', danger, busy, onConfirm, onCancel }) => (
  <Modal onClose={busy ? undefined : onCancel} labelledBy="confirm-title">
    <h2 id="confirm-title" className="text-[1.15rem] font-semibold tracking-tight pr-6">
      {title}
    </h2>
    {body && <p className="text-[14px] text-muted leading-relaxed mt-2">{body}</p>}
    <div className="flex items-center justify-end gap-1 mt-6">
      <Btn variant="quiet" onClick={onCancel} disabled={busy}>
        Cancel
      </Btn>
      <Btn variant={danger ? 'danger' : 'primary'} onClick={onConfirm} disabled={busy}>
        {busy ? (
          <>
            <Spinner /> Working…
          </>
        ) : (
          confirmLabel
        )}
      </Btn>
    </div>
  </Modal>
);

// ── Inline-SVG charts (no chart lib) ─────────────────────────────────────────────────────────────────────

// A compact line sparkline over `values` (numbers). Scales to its container width via viewBox.
export const Sparkline = ({ values = [], width = 240, height = 44, className = '' }) => {
  if (!values.length) return <div className="text-[12px] text-faint">No data yet.</div>;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(height - ((v - min) / span) * height).toFixed(1)}`);
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className={`w-full ${className}`} preserveAspectRatio="none" aria-hidden="true">
      <polyline points={pts.join(' ')} fill="none" stroke="var(--color-accent)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
};

// A vertical bar chart over `values`. For trend/day series.
export const BarChart = ({ values = [], height = 120, className = '' }) => {
  if (!values.length) return <div className="text-[12px] text-faint">No data yet.</div>;
  const max = Math.max(...values, 1);
  return (
    <div className={`flex items-end gap-[2px] ${className}`} style={{ height }} aria-hidden="true">
      {values.map((v, i) => (
        <div
          key={i}
          className="flex-1 min-w-[2px] rounded-t-sm bg-accent-fill/70"
          style={{ height: `${Math.max(2, (v / max) * 100)}%` }}
          title={String(v)}
        />
      ))}
    </div>
  );
};
