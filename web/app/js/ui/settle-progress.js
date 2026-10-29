import { h } from "./h.js";
import { facts } from "./facts.js";
import { route } from "../state/route.js";

const secs = (s) =>
  s < 60 ? `${Math.round(s)} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;

/**
 * A settlement on its way into a block: how long since it was sent, how many times the chain has
 * been asked, and how long the last answer took, which is the mixnet's share of the wait.
 */
export function settleProgress(watch) {
  const since = h("span", {}, "0 s");
  const checks = h("span", {}, "none yet");
  const latency = h("span", {}, "waiting");
  const note = h("p", { class: "lead" });
  const draw = () => {
    const waited = (Date.now() - watch.sentAt) / 1000;
    since.textContent = secs(waited);
    checks.textContent = watch.checks ? String(watch.checks) : "none yet";
    latency.textContent =
      watch.lastCheck == null
        ? "waiting"
        : `${watch.lastCheck.toFixed(1)} s ${route.nym ? "through the mixnet" : "direct"}`;
    note.textContent =
      waited < 40
        ? "A block comes about every 12 seconds. Most settlements land in the first or second."
        : watch.lastCheck > 8
          ? "The chain has been slow to answer through the mixnet. The settlement itself is already sent and does not depend on these checks."
          : "Still waiting for a block to include it. The network fee covers a busy block; nothing needs doing here.";
  };
  draw();
  const tick = setInterval(() => (since.isConnected ? draw() : clearInterval(tick)), 500);
  return [
    h("div", { class: "meter waiting", "aria-hidden": "true" }, h("span")),
    facts([
      ["sent", since],
      ["checks", checks],
      ["last answer", latency],
    ]),
    note,
  ];
}
