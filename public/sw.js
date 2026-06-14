// kunji Web Push service worker (push-relay.md Transport ②). It receives an OPAQUE pointer (a
// requestId) over Web Push and prompts the user; tapping the notification opens/focuses the wallet to
// the re-consent for that request. The SW never sees keys, scope, or request contents — only the
// pointer; the request itself rides the existing encrypted relay and is approved in the wallet UI.
self.addEventListener('push', (event) => {
  let requestId = '';
  try {
    requestId = (event.data && event.data.json().requestId) || '';
  } catch {
    requestId = '';
  }
  event.waitUntil(
    self.registration.showNotification('kunji — an app requests access', {
      body: 'Tap to review and approve in your wallet.',
      tag: requestId || 'kunji-push', // collapse duplicate pings for the same request
      data: { requestId },
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const requestId = (event.notification.data && event.notification.data.requestId) || '';
  const url = requestId ? `/?push=${encodeURIComponent(requestId)}` : '/';
  event.waitUntil(
    (async () => {
      const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const win of wins) {
        if ('focus' in win) {
          win.postMessage({ type: 'kunji-push', requestId }); // an open wallet handles it without a reload
          return win.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })(),
  );
});
