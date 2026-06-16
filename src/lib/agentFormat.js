// Shared agent-expiry formatting (used by AgentsSheet / AgentRow / AgentDetailsSheet). Local-only —
// no server tracks expiries; this is a client-side reminder derived from the capability's `exp`.
export const SOON_MS = 48 * 3_600_000; // "expiring soon" window — surfaced for re-authorization

export const expiryLabel = (expSeconds) => {
  if (!expSeconds) return '';
  const ms = expSeconds * 1000 - Date.now();
  if (ms <= 0) return 'expired';
  const h = Math.round(ms / 3_600_000);
  if (h < 48) return `expires in ${Math.max(1, h)}h`;
  return `expires in ${Math.round(h / 24)}d`;
};

export const expiryTone = (expSeconds) => {
  if (!expSeconds) return 'text-faint';
  const ms = expSeconds * 1000 - Date.now();
  if (ms <= 0) return 'text-danger';
  if (ms < SOON_MS) return 'text-accent';
  return 'text-faint';
};
