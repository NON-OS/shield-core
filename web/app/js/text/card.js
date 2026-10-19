/** The measurement as the apps' card writes it, with the lines a browser can fill in. */
export function card(r, app) {
  return [
    `proved: ${r.seconds.toFixed(1)} s (${Math.round(r.seconds * 1000)} ms)`,
    "verified: inside the time, true",
    `proof: ${r.proofBytes} bytes`,
    `queries: ${r.point[0]} at grind ${r.point[1]}`,
    `peak: ${Math.round(r.wasmBytes / 1024)} KiB`,
    `where: ${navigator.userAgent}; threads ${app.proving?.threads || 1}; release ${app.version}`,
  ].join("\n");
}
