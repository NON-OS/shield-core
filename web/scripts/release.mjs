// Build the site as it is deployed: static files and Cloudflare Pages' `_headers`, from this
// checkout and nothing else. Two builds of one commit give the same files, which the manifest
// hash shows in one line.
//
//   node web/scripts/release.mjs <out dir> [--dev]
//
// --dev builds a checkout with changes, for testing, and says so in the version.
//
// The threaded wasm is what the page runs. The one-thread wasm runs here, in Node, to build the
// periodic cache from the pinned test vector and to read the endpoints the core may reach, so
// both come from the core itself and not from a file kept by hand.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { pagesHeaders } from "./pages-headers.mjs";
import { licences } from "./licences.mjs";

const out = process.argv[2];
const dev = process.argv.includes("--dev");
if (!out) throw new Error("usage: node web/scripts/release.mjs <out dir> [--dev]");
const web = new URL("..", import.meta.url).pathname;
const core = join(web, "..");
const vector = join(core, "core/src/bench/profile/vector");
// Pages refuses a file over 25 MiB; chunks stay well under it.
const CHUNK = 16 * 1024 * 1024;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const git = (...args) => execFileSync("git", ["-C", core, ...args], { encoding: "utf8" }).trim();
if (!dev && git("status", "--porcelain")) {
  throw new Error("the checkout has changes, so its commit is not what would be built");
}
const commit = git("rev-parse", "HEAD");
const version = `${dev ? "dev" : "web"} ${commit.slice(0, 12)}`;

const work = mkdtempSync(join(tmpdir(), "shield-release-"));
for (const form of ["threads", "single"]) {
  execFileSync(join(web, "scripts/build-wasm.sh"), [form, join(work, form)], { stdio: "inherit" });
}

const single = await import(join(work, "single/pkg/nox_shield_web.js"));
single.initSync({ module: readFileSync(join(work, "single/pkg/nox_shield_web_bg.wasm")) });
const connect = JSON.parse(single.endpoint_hosts());
const entropy = Uint8Array.from(
  Buffer.from(readFileSync(join(vector, "entropy.hex"), "utf8").trim(), "hex"),
);
console.log("building the periodic cache from the pinned vector, on one thread");
const cache = single.periodic_cache(
  readFileSync(join(vector, "request.json"), "utf8"),
  readFileSync(join(vector, "seed.json"), "utf8"),
  entropy,
);
const tag = single.periodic_root().slice(0, 8);

// Everything the page loads but its entry files, in a directory named for its content.
const stage = join(work, "stage");
const skipped = (path) =>
  path.endsWith(".test.mjs") || ["index.html", "sw.js", "manifest.webmanifest"].includes(path);
const app = join(web, "app");
const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
for (const file of walk(app)) {
  const path = relative(app, file);
  if (skipped(path)) continue;
  mkdirSync(join(stage, path, ".."), { recursive: true });
  cpSync(file, join(stage, path));
}
cpSync(join(work, "threads/pkg"), join(stage, "pkg"), { recursive: true });
mkdirSync(join(stage, "prover/vector"), { recursive: true });
for (const name of ["request.json", "seed.json", "entropy.hex"]) {
  cpSync(join(vector, name), join(stage, "prover/vector", name));
}
const linked = licences(core);
mkdirSync(join(stage, "licences"), { recursive: true });
writeFileSync(join(stage, "licences/licences.txt"), linked.list);
writeFileSync(join(stage, "licences/licence-texts.txt"), linked.texts);
const chunks = [];
for (let at = 0, n = 0; at < cache.length; at += CHUNK, n++) {
  const part = cache.subarray(at, at + CHUNK);
  const name = `prover/periodic-${tag}.top.${n}`;
  writeFileSync(join(stage, name), part);
  chunks.push({ name, sha256: sha256(part) });
}

const listing = (dir) =>
  walk(dir)
    .map((file) => relative(dir, file))
    .sort()
    .map((path) => ({
      path,
      bytes: statSync(join(dir, path)).size,
      sha256: sha256(readFileSync(join(dir, path))),
    }));
const staged = listing(stage);
const dir = `r/${sha256(staged.map((f) => `${f.path} ${f.sha256}\n`).join("")).slice(0, 16)}`;

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, dir), { recursive: true });
cpSync(stage, join(out, dir), { recursive: true });
const at = (path) => `${dir}/${path}`;
const page = readFileSync(join(app, "index.html"), "utf8").replace(
  /(href|src)="(?!https?:)([^"]+)"/g,
  (_, attr, path) =>
    path === "manifest.webmanifest" ? `${attr}="${path}"` : `${attr}="${at(path)}"`,
);
writeFileSync(join(out, "index.html"), page);
// Every release is a new worker, so the browser installs it and the page can offer the update.
const worker = readFileSync(join(app, "sw.js"), "utf8");
if (!worker.includes('const RELEASE = "release-directory";'))
  throw new Error("sw.js has no release slot");
writeFileSync(
  join(out, "sw.js"),
  worker.replace('const RELEASE = "release-directory";', `const RELEASE = "${dir}";`),
);
const webManifest = JSON.parse(readFileSync(join(app, "manifest.webmanifest"), "utf8"));
webManifest.icons = webManifest.icons.map((icon) => ({ ...icon, src: at(icon.src) }));
writeFileSync(join(out, "manifest.webmanifest"), `${JSON.stringify(webManifest, null, 2)}\n`);
writeFileSync(join(out, "_headers"), pagesHeaders(connect, dir));
cpSync(join(web, "release/README.md"), join(out, "README.md"));

const served = listing(out).filter((f) => f.path !== "_headers");
const manifest = {
  version,
  commit,
  dir,
  connect,
  cache: {
    sha256: sha256(cache),
    chunks: chunks.map((c) => ({ path: at(c.name), sha256: c.sha256 })),
  },
  files: served,
};
const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
writeFileSync(join(out, "release-manifest.json"), manifestText);
const manifestHash = sha256(manifestText);
writeFileSync(join(out, "release.json"), `${JSON.stringify({ version, manifestHash }, null, 2)}\n`);
rmSync(work, { recursive: true, force: true });

const largest = Math.max(...served.map((f) => f.bytes));
console.log(`release ${version}, ${served.length} files, largest ${largest} bytes`);
console.log(`manifest sha256 ${manifestHash}`);
