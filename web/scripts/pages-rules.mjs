// Read a Cloudflare Pages `_headers` file the way Pages applies it: a rule is a path, exact or
// ending in a splat, and every rule that matches a request adds its headers.

export function pagesRules(text) {
  const rules = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) rules.push({ path: line.trim(), headers: {} });
    else {
      const at = line.indexOf(":");
      rules.at(-1).headers[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
  }
  const matches = (rule, path) =>
    rule.endsWith("/*") ? path.startsWith(rule.slice(0, -1)) : rule === path;
  return (path) =>
    Object.assign({}, ...rules.filter((r) => matches(r.path, path)).map((r) => r.headers));
}
