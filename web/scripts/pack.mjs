// The release as one zip for Cloudflare Pages' direct upload, "Create deployment" on the project.
// Files are deflated, in path order with no timestamps, so one release always packs to the same
// bytes, and the archive is kept under the 25 MiB the dashboard takes.
//
//   node web/scripts/pack.mjs <release dir> <zip file>

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { deflatedZip } from "./zip-deflate.mjs";

const [dir, out] = process.argv.slice(2);
if (!dir || !out) throw new Error("usage: node web/scripts/pack.mjs <release dir> <zip file>");
const walk = (d) =>
  readdirSync(d).flatMap((name) => {
    const path = join(d, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
const files = walk(dir)
  .map((path) => [relative(dir, path), new Uint8Array(readFileSync(path))])
  .sort(([a], [b]) => (a < b ? -1 : 1));
if (files.length > 1000) throw new Error(`${files.length} files, over the upload's 1,000`);
const big = files.find(([, bytes]) => bytes.length > 25 * 1024 * 1024);
if (big) throw new Error(`${big[0]} is over the 25 MiB a Pages file may be`);
const packed = deflatedZip(files);
if (packed.length > 25 * 1024 * 1024)
  throw new Error(`the zip is ${packed.length} bytes, over the 25 MiB the dashboard takes`);
writeFileSync(out, packed);
console.log(`${out}: ${files.length} files, ${packed.length} bytes`);
