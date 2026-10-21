// The service worker keeps one release's files, so the wallet opens without a network. Each file
// is fetched once, checked against the SHA-256 the release manifest gives for it, and kept with
// the headers it was served with, so a page opened from here is still cross-origin isolated and
// the threaded prover still runs. It caches nothing else: no reply from an RPC, and none of the
// wallet's data, which lives sealed in IndexedDB and never passes through here.
//
// The release build writes its directory into RELEASE, so every release is a new worker. A new
// one installs beside the old and waits; the page offers "Update ready", and only when the user
// takes it does the new worker take over, with a reload. A worker serves its own release's files
// and no other's, so two releases never serve one page between them.

const RELEASE = "release-directory";
const CACHE = `shield-${RELEASE}`;

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (buf) => hex(await crypto.subtle.digest("SHA-256", buf));

const unredirected = async (res) =>
  new Response(await res.arrayBuffer(), {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });

async function brokenBefore() {
  for (const key of await caches.keys()) {
    if (key === CACHE || !key.startsWith("shield-")) continue;
    const page = await (await caches.open(key)).match("./");
    if (page?.redirected) return true;
  }
  return false;
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const fresh = { cache: "no-store" };
      const head = await fetch("release.json", fresh);
      const listing = await fetch("release-manifest.json", fresh);
      const text = await listing.clone().arrayBuffer();
      const { manifestHash } = await head.clone().json();
      const manifest = JSON.parse(new TextDecoder().decode(text));
      if ((await sha256(text)) !== manifestHash || manifest.dir !== RELEASE) {
        throw new Error("the site now serves another release; this one is not installed");
      }
      const cache = await caches.open(CACHE);
      for (const file of manifest.files) {
        // Cloudflare Pages answers index.html with a redirect to the directory, and a redirected
        // response cannot answer a page load, so the page is fetched at its own address.
        const res = await fetch(file.path === "index.html" ? "./" : file.path, fresh);
        if (!res.ok || (await sha256(await res.clone().arrayBuffer())) !== file.sha256) {
          throw new Error(`${file.path} does not match the release manifest`);
        }
        // A redirected response can never answer a page load, so none is kept as one.
        const kept = res.redirected ? await unredirected(res) : res;
        await cache.put(file.path, kept.clone());
        if (file.path === "index.html") await cache.put("./", kept);
      }
      // A release whose worker kept the page as a redirect cannot open, so it can never offer
      // "Update ready". This one takes over from it at once instead of waiting.
      if (await brokenBefore()) await self.skipWaiting();
      await cache.put("release.json", head);
      await cache.put("release-manifest.json", listing);
    })(),
  );
});

self.addEventListener("message", (event) => {
  if (event.data === "take-update") self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== location.origin || event.request.method !== "GET") return;
  event.respondWith(
    caches
      .open(CACHE)
      .then((cache) => cache.match(event.request, { ignoreSearch: true }))
      .then((hit) => (hit && !hit.redirected ? hit : fetch(event.request))),
  );
});
