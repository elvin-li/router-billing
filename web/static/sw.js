// router-billing portal service worker.
//
// Cache-first for static assets so the portal page repaint is instant after
// the first visit. Network-first for everything else (api, admin, redeem)
// because freshness matters more than offline access for those.
//
// Bumped CACHE on every release so old assets get evicted.

const CACHE = 'rb-portal-v1';
const ASSETS = [
  '/static/style.css',
  '/static/portal.js',
  '/static/icon.svg',
  '/static/manifest.json',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Static assets: cache-first, fall back to network on miss.
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then((hit) => {
        if (hit) return hit;
        return fetch(event.request).then((res) => {
          // Only cache successful basic responses.
          if (res.ok && res.type === 'basic') {
            const clone = res.clone();
            caches.open(CACHE).then((c) => c.put(event.request, clone));
          }
          return res;
        });
      })
    );
    return;
  }

  // Everything else: network-first (passthrough; the portal page itself is
  // small enough that re-fetching on each visit is fine).
});
