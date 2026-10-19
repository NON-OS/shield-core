import { h } from "./h.js";

/** A button that shows `busy` and stays disabled while its action runs. */
export function button(label, action, { kind = "", busy = label, disabled = false } = {}) {
  const el = h("button", { type: "button", class: `button ${kind}`.trim(), disabled });
  el.textContent = label;
  el.addEventListener("click", async () => {
    if (el.disabled) return;
    el.disabled = true;
    el.textContent = busy;
    el.setAttribute("aria-busy", "true");
    try {
      await action();
    } finally {
      if (el.isConnected) {
        el.disabled = false;
        el.textContent = label;
        el.removeAttribute("aria-busy");
      }
    }
  });
  return el;
}
