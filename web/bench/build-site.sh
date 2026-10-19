#!/usr/bin/env bash
# Assemble the proof bench as a static site, for headless Chromium here or a real phone.
#
# Usage: web/bench/build-site.sh threads|single <out> <periodic cache>
#
# The site proves the pinned transfer-eth vector, whose seed opens two fixture notes under a root
# the pool does not know, so nothing in it spends anything. Serve <out> with the headers in
# web/scripts/headers.mjs over HTTPS (or on localhost), open index.html?threads=N&cache=1, and
# the page prints the time and the wasm memory when the proof is done. threads=0 is the
# single-thread package.
set -euo pipefail

form="${1:?threads or single}"
out="${2:?an output directory}"
cache="${3:?the periodic cache, from a first native or browser proof}"
here="$(cd "$(dirname "$0")" && pwd)"
core="$(cd "$here/../.." && pwd)"

"$core/web/scripts/build-wasm.sh" "$form" "$out"
cp "$here/index.html" "$here/bench.js" "$here/bench-worker.js" "$out/"
mkdir -p "$out/vector"
cp "$core/core/src/bench/profile/vector/"{request.json,seed.json,entropy.hex} "$out/vector/"
cp "$cache" "$out/periodic.top"
echo "bench site in $out"
