// Asking the browser to keep this site's storage. A deposit's note is kept only where it was
// made, until it is spent, and the recovery words do not bring an unspent deposit back, so storage
// a browser clears on its own would take those notes with it. A browser may still decline.

export const storage = {
  keep: () => navigator.storage?.persist?.().catch(() => false) ?? Promise.resolve(false),
  kept: () => navigator.storage?.persisted?.().catch(() => false) ?? Promise.resolve(false),
};
