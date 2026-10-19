// Copy to the clipboard and clear it a minute later, as the apps do, so an address or a key does
// not wait there for whatever reads the clipboard next.

const CLEAR_AFTER = 60_000;

export async function copyThenClear(text) {
  await navigator.clipboard.writeText(text);
  setTimeout(() => navigator.clipboard.writeText("").catch(() => undefined), CLEAR_AFTER);
}
