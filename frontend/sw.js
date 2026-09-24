/* frontend/sw.js — service worker для Web Push (VAPID) и PWA-шела.
   Сервер отдаёт его с Cache-Control: no-cache (см. backend/server.js), поэтому браузер
   всегда перечитывает при навигации — обновления подхватываются без ручного сброса. */

self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(clients.claim());
});

/* ----- Web Push ----- */
self.addEventListener('push', (e) => {
  let data = { title: 'REKA', body: '', url: '/', tag: 'space' };
  try {
    if (e.data) data = Object.assign(data, e.data.json());
  } catch (_) {}
  e.waitUntil(
    self.registration.showNotification(data.title || 'REKA', {
      body: data.body || '',
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      data: { url: data.url || '/' },
      tag: data.tag || 'space'
    })
  );
});

/* клик по уведомлению → открыть приложение на нужной странице */
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (new URL(c.url).origin === location.origin) {
          c.navigate(url);
          return c.focus();
        }
      }
      return self.clients.openWindow(url);
    })
  );
});
