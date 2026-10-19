// The licences of what the browser build links, as the apps list theirs: one line per crate,
// "name version : licence", from cargo's own view of the wasm dependency graph with threads, then
// the mixnet client's, kept in web/nym by nym-licences.mjs, then the two fonts; and the full texts
// each ships, one block per crate, separated by a form feed. Paths on the building machine never
// appear.

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const fonts = ["Geist : SIL Open Font License 1.1", "JetBrains Mono : SIL Open Font License 1.1"];

export function licences(core) {
  const run = (...args) =>
    execFileSync("cargo", args, { cwd: core, encoding: "utf8", maxBuffer: 1 << 28 });
  const tree = run(
    "tree",
    "-q",
    "-p",
    "nox_shield_web",
    "--features",
    "threads",
    "--target",
    "wasm32-unknown-unknown",
    "-e",
    "normal",
    "--prefix",
    "none",
    "--format",
    "{p}|{l}",
  );
  const crates = new Map();
  for (const line of tree.split("\n")) {
    const match = line.match(/^(\S+) v(\S+)(?: \([^)]*\))?\|(.*?)(?: \(\*\))?$/);
    if (match) crates.set(`${match[1]} ${match[2]}`, match[3] || "see its source");
  }
  const meta = JSON.parse(run("metadata", "--format-version", "1", "--locked"));
  const where = new Map(
    meta.packages.map((p) => [`${p.name} ${p.version}`, dirname(p.manifest_path)]),
  );
  const keys = [...crates.keys()].sort();
  const mixnet = (name) => readFileSync(join(core, "web/nym", name), "utf8").trim();
  const list = [...keys.map((k) => `${k} : ${crates.get(k)}`), mixnet("licences.txt"), ...fonts];
  const blocks = [];
  for (const key of keys) {
    const dir = where.get(key);
    if (!dir) continue;
    const files = readdirSync(dir)
      .filter((f) => /^(licen[cs]e|copying|notice)/i.test(f))
      .sort();
    for (const file of files)
      blocks.push(`${key}, ${file}\n\n${readFileSync(join(dir, file), "utf8").trim()}`);
  }
  blocks.push(mixnet("licence-texts.txt"));
  return { list: `${list.join("\n")}\n`, texts: `${blocks.join("\n\f\n")}\n` };
}
