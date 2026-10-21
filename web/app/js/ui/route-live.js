import { route } from "../state/route.js";

// What a request through the mixnet is doing while it travels, updated once a second in every
// status line on screen, so a slow request is never a silent one. It changes text only, never
// the screen, so nothing a user is typing is redrawn away.

const kb = (n) => (n < 1024 ? `${n} B` : `${Math.round(n / 1024)} KB`);

export function liveText() {
  const a = route.activity;
  if (!a) return "";
  const s = Math.round((Date.now() - a.since) / 1000);
  const what =
    route.tunnel === "connecting" ? "starting the tunnel" : `sending ${kb(a.bytes)} to ${a.host}`;
  return `${what}, ${s} s${a.attempt > 1 ? `, try ${a.attempt} of ${a.tries}` : ""}`;
}

setInterval(() => {
  const text = liveText();
  for (const el of document.querySelectorAll(".route-live"))
    el.textContent = text ? `  ·  ${text}` : "";
}, 1000);
