/* Role Finder service worker — install, push, notification click. */
const CACHE = 'rolefinder-v1';

self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(clients.claim());
});

self.addEventListener('push', (e) => {
  e.waitUntil((async () => {
    let data = null;
    try {
      const res = await fetch('data/latest.json', { cache: 'no-store' });
      data = await res.json();
    } catch (_) { /* offline or not published yet */ }

    const n = data && data.counts ? (data.counts.new_24h || 0) : 0;
    const items = (data && data.new_24h) || [];
    const lines = items.slice(0, 3).map((j) => (j.company || '') + ': ' + String(j.title || '').slice(0, 60));
    const body = lines.length
      ? lines.join('\n')
      : (data ? 'No new matches — check the dashboard.' : 'New roles available.');
    const title = n > 0
      ? n + ' new role' + (n > 1 ? 's' : '') + ' — Role Finder'
      : 'Role Finder scan complete';

    self.registration.showNotification(title, {
      body,
      icon: 'icons/icon-192.png',
      badge: 'icons/icon-192.png',
      data: { url: '/' },
    });
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) {
      if ('focus' in c) return c.focus();
    }
    return clients.openWindow((e.notification.data && e.notification.data.url) || '/');
  }));
});
