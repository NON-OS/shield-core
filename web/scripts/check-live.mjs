// Compare a live site with a release manifest, file by file, and check the headers the wallet's
// safety rests on. Exits 1 on any difference and names each one.
//
//   node web/scripts/check-live.mjs https://shield.nonos.app <manifest sha256>
//
// The manifest is fetched from the site itself and accepted only if it hashes to the value given,
// which comes from a build of the source or from somewhere other than the site.

import { createHash } from "node:crypto";
import { headers as expected } from "./headers.mjs";

const [origin, want] = process.argv.slice(2);
if (!origin || !/^[0-9a-f]{64}$/.test(want ?? "")) {
  throw new Error("usage: node web/scripts/check-live.mjs <origin> <manifest sha256>");
}
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const problems = [];
const get = async (path) => {
  const res = await fetch(new URL(path, origin), { cache: "no-store", redirect: "error" });
  return { res, bytes: Buffer.from(await res.arrayBuffer()) };
};

const { bytes: manifestBytes } = await get("release-manifest.json");
if (sha256(manifestBytes) !== want) {
  console.error(`the site's manifest hashes to ${sha256(manifestBytes)}, not ${want}`);
  process.exit(1);
}
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const release = JSON.parse((await get("release.json")).bytes.toString("utf8"));
if (release.manifestHash !== want)
  problems.push(`release.json names manifest ${release.manifestHash}`);

for (const file of manifest.files) {
  const { res, bytes } = await get(file.path);
  if (!res.ok) problems.push(`${file.path}: status ${res.status}`);
  else if (bytes.length !== file.bytes || sha256(bytes) !== file.sha256)
    problems.push(`${file.path}: differs`);
}

const { res: root } = await get("./");
for (const [name, value] of Object.entries(expected(manifest.connect))) {
  if (root.headers.get(name) !== value)
    problems.push(`header ${name}: ${root.headers.get(name) ?? "missing"}`);
}
const wasm = manifest.files.find((f) => f.path.endsWith(".wasm"));
const { res: wasmRes } = await get(wasm.path);
if (!wasmRes.headers.get("content-type")?.startsWith("application/wasm")) {
  problems.push(`${wasm.path}: served as ${wasmRes.headers.get("content-type")}`);
}
if (!wasmRes.headers.get("cache-control")?.includes("immutable")) {
  problems.push(`${wasm.path}: not cached as immutable`);
}
for (const path of ["./", "sw.js", "release.json"]) {
  const { res } = await get(path);
  if (!res.headers.get("cache-control")?.includes("no-cache"))
    problems.push(`${path}: cached without asking`);
}

if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(
  `${origin} serves release ${manifest.version}: ${manifest.files.length} files and every header match`,
);
