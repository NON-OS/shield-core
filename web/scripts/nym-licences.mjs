// The licences of the mixnet client the release serves, in the form licences.mjs gives the core's:
// the npm packages, the JavaScript mix-tunnel bundles into them, and every crate smolmix-wasm links
// for wasm32, from cargo's view of a Nym checkout at the commit the wasm names; then the full texts.
// The result is kept in web/nym, since a release is built from this checkout alone.
//
//   node web/scripts/nym-licences.mjs <nym checkout>
//
// mix-tunnel records ranges, not versions, for what it bundles, so the texts are those of the
// newest release in each range.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { nym } from "./nym.mjs";

const checkout = process.argv[2];
if (!checkout) throw new Error("usage: node web/scripts/nym-licences.mjs <nym checkout>");
const web = new URL("..", import.meta.url).pathname;
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 1 << 28 }).trim();
if (run("git", ["rev-parse", "HEAD"], checkout) !== nym.commit)
  throw new Error(`the checkout is not at ${nym.commit}, the commit smolmix-wasm was built from`);

const licenceFiles = (dir) =>
  readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying|notice)/i.test(f) && statSync(join(dir, f)).isFile())
    .sort();

const bundled = [
  ["comlink", "^4.3.1", "Apache-2.0"],
  ["rollup-plugin-web-worker-loader", "^1.6.1", "MIT"],
  ["@rollup/plugin-wasm", "^6.1.1", "MIT"],
];
const lines = Object.entries(nym.versions).map(([name, v]) => `${name} ${v} : Apache-2.0`);
const blocks = [
  `@nymproject/mix-fetch ${nym.versions["@nymproject/mix-fetch"]}, @nymproject/mix-tunnel ${nym.versions["@nymproject/mix-tunnel"]}, nym-smolmix-wasm and the nym crates, Apache-2.0\n\n${readFileSync(join(checkout, "LICENSES/Apache-2.0.txt"), "utf8").trim()}`,
];
const scratch = mkdtempSync(join(tmpdir(), "nym-licences-"));
for (const [name, range, licence] of bundled) {
  const version = JSON.parse(
    run("npm", ["view", `${name}@${range}`, "version", "--json"], scratch),
  );
  const latest = Array.isArray(version) ? version.at(-1) : version;
  lines.push(`${name} ${latest} : ${licence}, bundled in mix-tunnel`);
  const tgz = run("npm", ["pack", `${name}@${latest}`, "--silent"], scratch);
  const into = join(scratch, name.replace("/", "-"));
  execFileSync("mkdir", ["-p", into]);
  execFileSync("tar", ["xzf", join(scratch, tgz), "-C", into]);
  for (const file of licenceFiles(join(into, "package")))
    blocks.push(
      `${name} ${latest}, ${file}\n\n${readFileSync(join(into, "package", file), "utf8").trim()}`,
    );
}
rmSync(scratch, { recursive: true, force: true });

const tree = run(
  "cargo",
  [
    "tree",
    "-q",
    "-p",
    "nym-smolmix-wasm",
    "--target",
    "wasm32-unknown-unknown",
    "-e",
    "normal",
    "--prefix",
    "none",
    "--format",
    "{p}|{l}",
  ],
  checkout,
);
const crates = new Map();
for (const line of tree.split("\n")) {
  const match = line.match(/^(\S+) v(\S+)(?: \([^)]*\))?\|(.*?)(?: \(\*\))?$/);
  if (match) crates.set(`${match[1]} ${match[2]}`, match[3] || "see its source");
}
const meta = JSON.parse(run("cargo", ["metadata", "--format-version", "1", "--locked"], checkout));
const where = new Map(
  meta.packages.map((p) => [`${p.name} ${p.version}`, dirname(p.manifest_path)]),
);
// Most crates ship one of a few texts word for word, so each text appears once, after the names of
// every crate that ships it.
const shared = new Map();
for (const key of [...crates.keys()].sort()) {
  lines.push(`${key} : ${crates.get(key)}`);
  const dir = where.get(key);
  if (!dir || dir.startsWith(checkout)) continue;
  for (const file of licenceFiles(dir)) {
    const text = readFileSync(join(dir, file), "utf8").trim();
    shared.set(text, [...(shared.get(text) ?? []), `${key}, ${file}`]);
  }
}
for (const [text, names] of shared) blocks.push(`${names.join("\n")}\n\n${text}`);

writeFileSync(join(web, "nym/licences.txt"), `${lines.join("\n")}\n`);
writeFileSync(join(web, "nym/licence-texts.txt"), `${blocks.join("\n\f\n")}\n`);
console.log(`${lines.length} entries, ${blocks.length} texts`);
