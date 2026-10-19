import { h } from "./h.js";
import { glyph } from "./glyph.js";

/** A round action: a cyan circle with its sign, and its name under it. */
export function roundAction(title, sign, action, { disabled = false } = {}) {
  return h(
    "button",
    { type: "button", class: "round-action", onclick: action, disabled },
    h("span", { class: "circle" }, glyph(sign)),
    h("span", {}, title),
  );
}
