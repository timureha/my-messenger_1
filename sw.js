self.addEventListener('push', event => {
    if (!event.data) return;
    let data;
    try { data = event.data.json(); } catch { return; }
    event.waitUntil(
        self.registration.showNotification(data.title || 'Messenger', {
            body: data.body || '',
            icon: '/icon-192.png',
            badge: '/icon-192.png',
            tag: data.tag || 'msg',
            renotify: true,
            vibrate: [200, 100, 200],
        })
    );
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
            for (const c of list) { if ('focus' in c) return c.focus(); }
            if (clients.openWindow) return clients.openWindow('/');
        })
    );
});
