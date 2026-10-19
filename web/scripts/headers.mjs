// The response headers every file of the site is served with, from the list of endpoints the core
// may reach and the hosts of the mixnet. The development server and the Cloudflare Pages
// `_headers` file are both made from this, so what is tested is what is deployed.
//
// COOP and COEP make the page cross-origin isolated, the only way a browser hands it shared memory:
// for the threaded prover, and for the wallet's worker to wait on its requests. The CSP allows
// script, style, fonts and workers from the site alone; 'wasm-unsafe-eval' lets it compile its own
// wasm and the mixnet client's, and nothing else; connections go to the site, to Nym's directory
// and pinned gateways, and to the listed endpoints, which the page reaches only when the user has
// chosen to connect directly. HSTS covers this host and not its parent zone, whose other hosts are
// not this site's to bind.

const unused = [
  "accelerometer",
  "autoplay",
  "browsing-topics",
  "camera",
  "display-capture",
  "encrypted-media",
  "fullscreen",
  "geolocation",
  "gyroscope",
  "hid",
  "idle-detection",
  "magnetometer",
  "microphone",
  "midi",
  "payment",
  "picture-in-picture",
  "screen-wake-lock",
  "serial",
  "usb",
  "xr-spatial-tracking",
];

export function headers(connect, mixnet = []) {
  return {
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "worker-src 'self'",
      ["connect-src 'self'", ...mixnet, ...connect.map((host) => `https://${host}`)].join(" "),
      "img-src 'self' data:",
      "style-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join("; "),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Permissions-Policy": [
      ...unused.map((f) => `${f}=()`),
      "clipboard-write=(self)",
      "publickey-credentials-create=(self)",
      "publickey-credentials-get=(self)",
    ].join(", "),
    "Strict-Transport-Security": "max-age=63072000",
  };
}
