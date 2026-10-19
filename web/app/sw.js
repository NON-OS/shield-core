// The service worker keeps the release's own files, so the wallet opens without a network. It
// caches nothing but those files: no reply from an RPC, and none of the wallet's data, which lives
// sealed in IndexedDB and never passes through here. A new release is taken only once every one
// of its files has arrived, so a half-fetched release is never what opens.

async function files() {
  const fresh = { cache: "no-store" };
  const release = await (await fetch("release.json", fresh)).json();
  const manifest = await (await fetch("release-manifest.json", fresh)).json();
  const paths = [
    "./",
    "release.json",
    "release-manifest.json",
    ...manifest.files.map((f) => f.path),
  ];
  return { name: `shield-${release.manifestHash}`, paths };
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const { name, paths } = await files();
      const cache = await caches.open(name);
      await cache.addAll(paths.map((p) => new Request(p, { cache: "no-store" })));
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const { name } = await files().catch(() => ({ name: null }));
      for (const key of await caches.keys()) if (name && key !== name) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== location.origin || event.request.method !== "GET") return;
  event.respondWith(caches.match(event.request).then((hit) => hit ?? fetch(event.request)));
});
