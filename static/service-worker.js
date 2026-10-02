// Genga Gamble Service Worker
// Strategie: Network-First für HTML/API, Cache-First für statische Assets

const CACHE_VERSION = 'genga-v1';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;

// Diese Dateien werden beim Install gecached (App-Shell)
const PRECACHE_URLS = [
  '/static/manifest.json',
  '/static/icon.svg'
];

// ============ INSTALL ============
self.addEventListener('install', (event) => {
  console.log('[SW] Install');
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => {
      return cache.addAll(PRECACHE_URLS).catch(err => {
        console.warn('[SW] Precache-Fehler:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// ============ ACTIVATE ============
self.addEventListener('activate', (event) => {
  console.log('[SW] Activate');
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter(key => !key.startsWith(CACHE_VERSION))
            .map(key => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// ============ FETCH ============
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Nur GET-Requests
  if (req.method !== 'GET') return;

  // Nur eigene Domain
  if (url.origin !== self.location.origin) return;

  // API-Requests: NIEMALS cachen (Guthaben muss live sein!)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(req));
    return;
  }

  // Admin: nie cachen
  if (url.pathname.startsWith('/admin')) {
    event.respondWith(fetch(req));
    return;
  }

  // Statische Assets (Icons, Manifest): Cache-First
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(req).then(cached => cached || fetch(req).then(res => {
        const clone = res.clone();
        caches.open(STATIC_CACHE).then(cache => cache.put(req, clone));
        return res;
      }))
    );
    return;
  }

  // HTML + alles andere: Network-First (immer aktuell!)
  event.respondWith(
    fetch(req)
      .then(res => {
        // Nur erfolgreiche Antworten cachen
        if (res && res.status === 200 && res.type === 'basic') {
          const clone = res.clone();
          caches.open(RUNTIME_CACHE).then(cache => cache.put(req, clone));
        }
        return res;
      })
      .catch(() => {
        // Offline: aus Cache laden
        return caches.match(req).then(cached => {
          if (cached) return cached;
          // Fallback für HTML
          if (req.headers.get('accept')?.includes('text/html')) {
            return caches.match('/');
          }
          return new Response('Offline', { status: 503 });
        });
      })
  );
});

// ============ MESSAGE (für Update-Trigger) ============
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
