import { h } from "./h.js";
import { estimate, steps } from "../state/proof-progress.js";
import { meter } from "../state/net-meter.js";
import { route } from "../state/route.js";

const secs = (s) => `${Math.round(s)} s`;

function leftText(e, active) {
  if (active?.network) return route.nym ? "Waiting on the mixnet" : "Waiting on the network";
  if (e.left == null) return "Timing this device";
  if (e.left < 5) return "A few seconds left";
  if (e.left < 60) return `About ${Math.max(5, Math.round(e.left / 5) * 5)} s left`;
  const m = Math.floor(e.left / 60);
  const s = Math.round((e.left % 60) / 10) * 10;
  return `About ${m} min${s ? ` ${s} s` : ""} left`;
}

// What the network step has done so far, from the page's own count of the requests it carried.
function networkNote() {
  if (!route.nym) return "Direct, not through the mixnet";
  const m = meter();
  if (!m.done) return "First request out through the mixnet";
  const n = m.done === 1 ? "1 request" : `${m.done} requests`;
  return `${n} through the mixnet, the last took ${m.lastSeconds.toFixed(1)} s`;
}

/**
 * The running proof: how far it is, how long is left, and each step as the prover finishes it.
 * It redraws itself four times a second and stops once it leaves the page.
 */
export function proofProgress() {
  const share = h("span", { class: "number" }, "0");
  const left = h("span", { class: "left" });
  const fill = h("span");
  const bar = h(
    "div",
    { class: "meter", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100" },
    fill,
  );
  const elapsed = h("span", {}, "0 s");
  const items = steps().map((s) => {
    const took = h("span", { class: "took" });
    const note = s.network ? h("span", { class: "note" }) : null;
    const li = h(
      "li",
      {},
      h("span", { class: "mark", "aria-hidden": "true" }),
      h("span", {}, s.label),
      took,
      note,
    );
    return { li, took, note };
  });
  const list = h(
    "ol",
    { class: "phases" },
    items.map((i) => i.li),
  );
  const draw = () => {
    const e = estimate();
    if (!e) return;
    const pct = Math.floor(e.share * 100);
    const active = e.steps.findIndex((s) => s.took == null);
    share.textContent = String(pct);
    fill.style.width = `${e.share * 100}%`;
    bar.setAttribute("aria-valuenow", String(pct));
    left.textContent = leftText(e, e.steps[active]);
    elapsed.textContent = secs(e.elapsed);
    e.steps.forEach((s, i) => {
      const { li, took, note } = items[i];
      li.className = s.took != null ? "done" : i === active ? "active" : "";
      if (i === active) li.setAttribute("aria-current", "step");
      else li.removeAttribute("aria-current");
      took.textContent = s.took != null ? secs(s.took) : "";
      if (note) note.textContent = i === active || s.took != null ? networkNote() : "";
    });
  };
  draw();
  const tick = setInterval(() => (bar.isConnected ? draw() : clearInterval(tick)), 250);
  return {
    meter: h(
      "div",
      { class: "proof-progress" },
      h("p", { class: "figure" }, share, h("span", { class: "unit" }, "%"), left),
      bar,
      list,
    ),
    elapsed,
  };
}
