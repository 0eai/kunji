// kunji Web Push service worker (push-relay.md Transport ②). It receives an OPAQUE pointer (a
// requestId) over Web Push and prompts the user; tapping the notification (or, for a foreground wallet,
// the push itself) opens the wallet to the re-consent for that request. The SW never sees keys, scope, or
// request contents — only the pointer; the request itself rides the existing encrypted relay.

// Activate a new SW immediately (no "waiting" behind the old one) and take control of open pages — so a
// shipped fix to this file takes effect on the next load, not only after the PWA is fully killed + reopened.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// Stash the pointer where a SUSPENDED/backgrounded wallet (esp. iOS PWAs) can read it on resume — a
// postMessage to a suspended client is dropped before its listener re-attaches, and focusing an existing
// window doesn't apply a `?push=` URL. The wallet drains '/__kunji_pending_push' on visibilitychange/load.
const stash = async (requestId) => {
  if (!requestId) return;
  try {
    const cache = await caches.open('kunji-push');
    await cache.put('/__kunji_pending_push', new Response(requestId));
  } catch {
    /* Cache unavailable — the postMessage / ?push= paths still cover the live cases */
  }
};

const readRequestId = (event) => {
  try {
    return (event.data && event.data.json().requestId) || '';
  } catch {
    return '';
  }
};

self.addEventListener('push', (event) => {
  const requestId = readRequestId(event);
  event.waitUntil(
    (async () => {
      await stash(requestId);
      // Nudge a FOREGROUND/visible wallet so it opens the sheet without needing a tap (iOS often shows no
      // tappable banner while the PWA is in the foreground).
      if (requestId) {
        try {
          const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
          for (const w of wins) if (w.visibilityState === 'visible') w.postMessage({ type: 'kunji-push', requestId });
        } catch {
          /* best-effort */
        }
      }
      await self.registration.showNotification('kunji — an app requests access', {
        body: 'Tap to review and approve in your wallet.',
        tag: requestId || 'kunji-push', // collapse duplicate pings for the same request
        data: { requestId },
        icon: '/icons/icon-192.png',
        badge: '/icons/icon-192.png',
      });
    })(),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const requestId = (event.notification.data && event.notification.data.requestId) || '';
  const url = requestId ? `/?push=${encodeURIComponent(requestId)}` : '/';
  event.waitUntil(
    (async () => {
      await stash(requestId); // the reliable hand-off; the wallet drains it on resume
      const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const win of wins) {
        if ('focus' in win) {
          win.postMessage({ type: 'kunji-push', requestId }); // fast path for a live (desktop/Android) wallet
          return win.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })(),
  );
});
