// Per-device session preferences — how long the vault stays unlocked here, and whether the
// unlocked master key survives a reload. All three are LOCAL to this device (localStorage):
// they're UX policy, not vault data, and deliberately don't sync to linked devices.
//
// `kunji_autolock` and `kunji_lock_on_hidden` predate this module — App.jsx read them directly but
// nothing ever wrote them, so auto-lock was a fixed 20h and lock-on-hidden was unreachable. The key
// names are kept byte-identical (any hand-set value still applies); the Security sheet now writes them.

const AUTOLOCK_KEY = 'kunji_autolock';
const LOCK_ON_HIDDEN_KEY = 'kunji_lock_on_hidden';
const STAY_UNLOCKED_KEY = 'kunji_stay_unlocked';
const SESSION_SEEN_KEY = 'kunji_session_seen';

// Private mode / blocked storage throws on access, and a preference that won't persist must never
// break the app — same posture as services/push.js.
const read = (key) => {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
};
const write = (key, value) => {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage blocked — the preference just won't persist */
  }
};

/**
 * Auto-lock choices, in minutes. 0 = never (only an explicit lock, or closing the tab).
 * `short` is for the segmented picker — the full labels can't fit five options on one phone-width
 * row, and wrapping one option onto a second row reads as broken. `label` is the spelled-out form
 * shown on the collapsed row, where there's room and clarity matters more.
 */
export const AUTO_LOCK_OPTIONS = [
  { minutes: 15, label: '15 min', short: '15m' },
  { minutes: 60, label: '1 hour', short: '1h' },
  { minutes: 240, label: '4 hours', short: '4h' },
  { minutes: 1200, label: '20 hours', short: '20h' },
  { minutes: 0, label: 'Never', short: 'Never' },
];

export const AUTO_LOCK_DEFAULT_MIN = 1200; // 20 hours — the long-standing default

/**
 * Stored string → a usable minutes value. Anything unparseable falls back to the default: the old
 * inline `parseInt(saved)` turned a junk value into NaN, which then failed the `if (timeout)` guard
 * and silently disabled auto-lock altogether.
 */
export const parseAutoLockMinutes = (raw) => {
  if (raw == null || raw === '') return AUTO_LOCK_DEFAULT_MIN;
  const n = Number.parseInt(raw, 10);
  if (!Number.isInteger(n) || n < 0) return AUTO_LOCK_DEFAULT_MIN;
  return Math.min(n, 30 * 24 * 60); // 30 days, matching the saved-session TTL
};

// setTimeout wraps past 2^31-1 ms and fires IMMEDIATELY, so an absurd hand-set `kunji_autolock`
// would turn auto-lock into lock-on-every-interaction. ~24.8 days is the largest delay a timer can
// actually hold; clamping here covers both the timer and the idle comparison in deviceSession.
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

export const getAutoLockMinutes = () => parseAutoLockMinutes(read(AUTOLOCK_KEY));
export const setAutoLockMinutes = (minutes) => write(AUTOLOCK_KEY, String(minutes));

/** The idle timeout in ms, or null when auto-lock is off. */
export const autoLockMs = (minutes = getAutoLockMinutes()) =>
  minutes > 0 ? Math.min(minutes * 60000, MAX_TIMEOUT_MS) : null;

/** Lock as soon as the tab is hidden. Off by default — aggressive, but some people want it. */
export const getLockOnHidden = () => read(LOCK_ON_HIDDEN_KEY) === 'true';
export const setLockOnHidden = (on) => write(LOCK_ON_HIDDEN_KEY, on ? 'true' : 'false');

/** "Stay unlocked on this device" — see services/deviceSession.js. Off by default, always. */
export const getStayUnlocked = () => read(STAY_UNLOCKED_KEY) === 'on';
export const setStayUnlocked = (on) => write(STAY_UNLOCKED_KEY, on ? 'on' : 'off');

/*
 * When the vault was last known-unlocked on this device — the clock that lets the auto-lock setting
 * apply to a saved session too, not just to a tab that happens to be open. Deliberately
 * localStorage and not part of the IndexedDB record: writes here are SYNCHRONOUS, so the revocation
 * below is durable the instant a lock happens, even if the page is frozen or killed before the
 * (async) IndexedDB delete commits. 0 means "revoked" and fails closed, as does unreadable storage.
 */
export const getSessionSeen = () => {
  const n = Number.parseInt(read(SESSION_SEEN_KEY), 10);
  return Number.isInteger(n) && n > 0 ? n : 0;
};
export const setSessionSeen = (ms) => write(SESSION_SEEN_KEY, String(ms));
export const revokeSessionSeen = () => write(SESSION_SEEN_KEY, '0');
