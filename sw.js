// Service worker mínimo do CIPHER Scanner.
// Faz cache do "shell" estático (o próprio index.html) para abrir mais rápido
// em visitas repetidas. NÃO armazena nem intercepta chamadas à API do
// backend (/api/scanner/...) — essas continuam sempre indo direto à rede,
// já que são análises que precisam de dados em tempo real.
const CACHE_NAME = 'cipher-shell-v1';
const ARQUIVOS_ESTATICOS = ['./', './index.html', './manifest.json', './icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ARQUIVOS_ESTATICOS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((chaves) =>
      Promise.all(chaves.filter((c) => c !== CACHE_NAME).map((c) => caches.delete(c)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Nunca faz cache de chamadas à API — elas precisam ser sempre em tempo real.
  if (url.pathname.startsWith('/api/')) return;
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then((cacheado) => cacheado || fetch(event.request))
  );
});
