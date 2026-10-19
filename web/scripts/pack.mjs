// The release as one zip for Cloudflare Pages' direct upload, "Create deployment" on the project.
// Files are stored in path order with no timestamps, so one release always packs to the same bytes.
//
//   node web/scripts/pack.mjs <release dir> <zip file>

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { zip } from "../app/js/files/zip.js";

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
writeFileSync(out, Buffer.from(await zip(files).arrayBuffer()));
console.log(`${out}: ${files.length} files`);
