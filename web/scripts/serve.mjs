// A static server for development and the browser tests, sending the site's headers.
//
//   node web/scripts/serve.mjs <dir> [port]
//
// It binds to the loopback address only and serves nothing outside <dir>.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { headers } from "./headers.mjs";
import { pagesRules } from "./pages-rules.mjs";

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".webmanifest": "application/manifest+json",
  ".wasm": "application/wasm",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

const root = resolve(process.argv[2] ?? ".");
const port = Number(process.argv[3] ?? 8787);
// The endpoints a release lists. A site without a manifest, such as the bench, reaches none.
const listed = join(root, "release-manifest.json");
const connect = existsSync(listed) ? JSON.parse(readFileSync(listed, "utf8")).connect : [];
const sent = headers(connect);
// A built release carries Cloudflare's `_headers`, and then this server applies it as Pages would.
const rulesFile = join(root, "_headers");
const rules = existsSync(rulesFile) ? pagesRules(readFileSync(rulesFile, "utf8")) : null;
const headersFor = (path) => (rules ? rules(path) : { ...sent, "Cache-Control": "no-cache" });

createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  let file = normalize(join(root, path));
  if (file !== root && !file.startsWith(root + sep)) {
    res.writeHead(403).end();
    return;
  }
  try {
    if ((await stat(file)).isDirectory()) file = join(file, "index.html");
    const body = await readFile(file);
    res.writeHead(200, {
      ...headersFor(path),
      "Content-Type": types[extname(file)] ?? "application/octet-stream",
    });
    res.end(body);
  } catch {
    res.writeHead(404, headersFor(path)).end();
  }
}).listen(port, "127.0.0.1", () => console.log(`serving ${root} on http://127.0.0.1:${port}`));
