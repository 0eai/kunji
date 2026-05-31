// Shared formatting for the activity log — used by SecurityPanel and AppDetailsModal
// so the icon/colour maps and relative-time logic don't drift between the two.
import {
  Unlock, Lock, ShieldCheck, ShieldX, AlertTriangle, Smartphone,
  Link as LinkIcon, Unlink, RotateCcw, CheckCircle2, Circle,
} from 'lucide-react';

export const ACTIVITY_ICONS = {
  Unlock, Lock, ShieldCheck, ShieldX, AlertTriangle, Smartphone,
  Link: LinkIcon, Unlink, RotateCcw, CheckCircle: CheckCircle2,
};

export const TYPE_COLOR = { success: 'text-success', danger: 'text-danger', info: 'text-muted' };

/** Resolve a stored activity icon name to a lucide component (Circle fallback). */
export const activityIcon = (name) => ACTIVITY_ICONS[name] || Circle;

/** Relative time from a Firestore Timestamp (or {seconds}). */
export const relTime = (createdAt) => {
  const ms = createdAt?.toMillis ? createdAt.toMillis() : (createdAt?.seconds ? createdAt.seconds * 1000 : null);
  if (!ms) return '';
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
