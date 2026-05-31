// Light / Dark / System theme control. Mirrors the no-flash boot script in
// index.html so runtime changes match what's applied on first paint.
const KEY = 'kunji_theme';
const PAPER = { light: '#faf9f6', dark: '#121110' };

const systemDark = () =>
  window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

/** @returns {'light'|'dark'|'system'} */
export const getThemePref = () => localStorage.getItem(KEY) || 'system';

const effectiveDark = (pref = getThemePref()) =>
  pref === 'dark' || (pref === 'system' && systemDark());

/** Apply the current preference: toggle `.dark`, sync the html bg + theme-color meta. */
export function applyTheme() {
  const dark = effectiveDark();
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.style.background = dark ? PAPER.dark : PAPER.light;
  const m = document.querySelector('meta[name="theme-color"]');
  if (m) m.setAttribute('content', dark ? PAPER.dark : PAPER.light);
}

/** Persist a new preference and apply it immediately. */
export function setThemePref(pref) {
  localStorage.setItem(KEY, pref);
  applyTheme();
}

/** Re-apply when the OS theme changes, but only while preference is `system`. */
export function watchSystem() {
  if (!window.matchMedia) return;
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (getThemePref() === 'system') applyTheme();
  });
}
