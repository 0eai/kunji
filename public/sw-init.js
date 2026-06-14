// Registers the kunji service worker (Web Push, push-relay.md Transport ②). External script so it runs
// under the CSP (script-src 'self') without inlining — same pattern as theme-init.js. Best-effort: the
// wallet works fully without it; push is opt-in and only matters once the user enables notifications.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((e) => console.warn('kunji SW registration failed:', e));
  });
}
