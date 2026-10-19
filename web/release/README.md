# NØNOS Wallet on the web, as served

These are the built files of the web wallet at https://shield.nonos.app, exactly as Cloudflare Pages
serves them, with the `_headers` file it reads. Nothing here is built on Cloudflare's side. The
source is the `shield-web` branch of `NON-OS/shield-core`, at the commit `release-manifest.json`
names.

## Check what is served

`release-manifest.json` lists every file with its size and SHA-256, and `release.json` gives the
manifest's own hash. From a checkout of the source:

    node web/scripts/check-live.mjs https://shield.nonos.app <manifest sha256>

It fetches every file the manifest lists from the live site and compares each one, and checks the
response headers the page depends on. It fails on the first difference.

## Rebuild and compare

From a clean checkout of the commit in `release-manifest.json`, with the toolchains it names:

    cd web && npm ci && cd ..
    node web/scripts/release.mjs /tmp/shield-site

The manifest hash it prints must be the one in `release.json`. Two builds of one commit, on two
machines, give the same bytes.
