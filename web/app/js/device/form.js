// Whether this is a phone or tablet, the devices whose browsers give a page the least memory.
// iPadOS reports itself as a Mac, and the touch points give it away.

export function handheld() {
  if (navigator.userAgentData) return navigator.userAgentData.mobile;
  const ua = navigator.userAgent;
  return (
    /iPhone|iPad|iPod|Android/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)
  );
}
