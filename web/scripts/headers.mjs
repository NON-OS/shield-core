// The response headers every file of the site is served with. The dev server and the hosting
// snippets are both generated from this list, so what is tested is what is deployed.
//
// COOP and COEP make the page cross-origin isolated, the only way a browser hands it
// SharedArrayBuffer and so the threaded prover. The CSP allows no script, style or font from
// anywhere but the site itself; 'wasm-unsafe-eval' lets it compile its own wasm and nothing
// else. connect-src is the one opening: the wallet talks to RPC endpoints the user picks, so any
// https origin is allowed there, and the page decides which one from the user's settings.
export const headers = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self'",
    "connect-src 'self' https:",
    "img-src 'self' data:",
    "style-src 'self'",
    "font-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; "),
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Permissions-Policy":
    "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), " +
    "publickey-credentials-create=(self), publickey-credentials-get=(self)",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
};
