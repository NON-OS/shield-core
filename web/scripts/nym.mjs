// The mixnet client as the release serves it, from the packages package-lock.json pins and npm ci
// checked. mix-fetch is served as published, with its one import pointed at the file beside it.
// mix-tunnel inlines the Nym client's worker as base64 and starts it from a blob: URL, which the
// page's CSP refuses, so its worker is written out as a file of its own, decoded from the base64
// as the blob is, and the one line that made the blob starts that file instead. Each result is
// checked against a pinned SHA-256, so a different package fails the build.
//
// The worker holds smolmix-wasm, built from the Nym repository at the commit below, which the wasm
// names itself; web/scripts/nym-licences.mjs lists what it links from that commit.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { nymHosts } from "../app/js/route/hosts.js";

const pinned = {
  "mix-fetch.js": "a7ba140c5c56706658babebce30263eb0454a70a0541a5f0f11bf47a8535c7ae",
  "mix-tunnel.js": "385fc5128192b04609cc98c659d02deaeaa8c94737eccfe5c3fd6943f145bd0d",
  "tunnel.js": "b0575ea1592d06830acd6837a559a16d21e3714967b80409a706364df4dda482",
};

function swap(text, from, to, what) {
  const at = text.indexOf(from);
  if (at < 0 || text.indexOf(from, at + 1) >= 0) throw new Error(`${what} is not as pinned`);
  return text.slice(0, at) + to + text.slice(at + from.length);
}

export const nym = {
  versions: { "@nymproject/mix-fetch": "3.0.0", "@nymproject/mix-tunnel": "0.3.0" },
  commit: "564b2ede29d499189eaa46e82cc4437ba4a8d76c",

  /** What the page's CSP lets the mixnet client reach. */
  sources() {
    return [
      ...nymHosts.api.map((host) => `https://${host}`),
      // Any gateway the directory lists, on the ports gateways serve wss on.
      ...nymHosts.ports.map((port) => `wss://*:${port}`),
    ];
  },

  /** The files to serve under nym/, by name. */
  files(web) {
    const modules = join(web, "node_modules/@nymproject");
    for (const [name, version] of Object.entries(this.versions)) {
      const at = join(modules, name.split("/")[1], "package.json");
      const found = JSON.parse(readFileSync(at, "utf8")).version;
      if (found !== version) throw new Error(`${name} is ${found}, not ${version}; run npm ci`);
    }
    const fetchText = readFileSync(join(modules, "mix-fetch/dist/index.js"), "utf8");
    const tunnelText = readFileSync(join(modules, "mix-tunnel/dist/esm/index.js"), "utf8");
    const inlined = tunnelText.match(
      /^var WorkerFactory = \/\*#__PURE__\*\/createBase64WorkerFactory\('([A-Za-z0-9+/=]+)', null, false\);$/m,
    );
    if (!inlined) throw new Error("mix-tunnel's worker is not where it is pinned");
    // What mix-tunnel's createURL puts in the blob: the source after its first line.
    const source = Buffer.from(inlined[1], "base64");
    const files = {
      "mix-fetch.js": swap(
        fetchText,
        "from '@nymproject/mix-tunnel';",
        'from "./mix-tunnel.js";',
        "mix-fetch's import",
      ),
      "mix-tunnel.js": swap(
        tunnelText,
        inlined[0],
        'function WorkerFactory(options) { return new Worker(new URL("./tunnel.js", import.meta.url), options); }',
        "mix-tunnel's worker",
      ),
      "tunnel.js": source.subarray(source.indexOf(10, 10) + 1),
    };
    for (const [name, bytes] of Object.entries(files)) {
      const hash = createHash("sha256").update(bytes).digest("hex");
      if (hash !== pinned[name]) throw new Error(`nym/${name} hashes to ${hash}, not as pinned`);
    }
    return files;
  },
};
