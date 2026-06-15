// Light / Dark / System theme control — mirrors the wallet's (app.kunji.cc) so the issuer matches.
const KEY = 'kunji_theme';
const PAPER = { light: '#faf9f6', dark: '#121110' };

const systemDark = () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

export const getThemePref = () => localStorage.getItem(KEY) || 'system';

const effectiveDark = (pref = getThemePref()) => pref === 'dark' || (pref === 'system' && systemDark());

export function applyTheme() {
  const dark = effectiveDark();
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.style.background = dark ? PAPER.dark : PAPER.light;
  const m = document.querySelector('meta[name="theme-color"]');
  if (m) m.setAttribute('content', dark ? PAPER.dark : PAPER.light);
}

export function setThemePref(pref) {
  localStorage.setItem(KEY, pref);
  applyTheme();
}

export function watchSystem() {
  if (!window.matchMedia) return;
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (getThemePref() === 'system') applyTheme();
  });
}
