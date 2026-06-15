// No-flash theme boot (external so it runs before paint under CSP script-src 'self'). Mirrors the wallet's
// boot script — applies the saved/system theme to <html> before the bundle mounts. PAPER colors kept in sync
// with src/index.css (@theme --color-paper + html.dark) and src/theme.js.
(function () {
  try {
    var pref = localStorage.getItem('kunji_theme') || 'system';
    var dark =
      pref === 'dark' ||
      (pref === 'system' &&
        window.matchMedia &&
        window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.style.background = dark ? '#121110' : '#faf9f6';
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', dark ? '#121110' : '#faf9f6');
  } catch {}
})();
