// No-flash theme boot. Loaded as an external script (CSP script-src 'self') so it
// runs before paint without violating the policy. Applies the saved/system theme
// to <html> before the bundle mounts.
// NOTE: the paper colors below must stay in sync with src/lib/theme.js (PAPER),
// index.css (@theme --color-paper), and manifest.json (theme_color).
(function () {
  try {
    var pref = localStorage.getItem('kunji_theme') || 'system';
    var dark = pref === 'dark' || (pref === 'system' &&
      window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.style.background = dark ? '#121110' : '#faf9f6';
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', dark ? '#121110' : '#faf9f6');
  } catch (e) {}
})();
