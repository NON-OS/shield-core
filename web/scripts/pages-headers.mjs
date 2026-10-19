// The `_headers` file Cloudflare Pages reads: the site's headers on every path, files under the
// release directory cached for good, since their path changes with their content, and the few
// files that name the release never cached without asking again.

import { headers } from "./headers.mjs";

const fresh = [
  "/",
  "/index.html",
  "/sw.js",
  "/release.json",
  "/release-manifest.json",
  "/manifest.webmanifest",
];

export function pagesHeaders(connect, dir) {
  const lines = ["/*"];
  for (const [name, value] of Object.entries(headers(connect))) lines.push(`  ${name}: ${value}`);
  lines.push("", `/${dir}/*`, "  Cache-Control: public, max-age=31536000, immutable");
  for (const path of fresh) lines.push("", path, "  Cache-Control: no-cache");
  return `${lines.join("\n")}\n`;
}
