import { h } from "./h.js";

/** A long value, an address or a hash, grouped in runs of eight with its length under it. */
export function valueBlock(value, label) {
  const groups = value.match(/.{1,8}/g)?.join(" ") ?? "";
  return h(
    "div",
    { class: "value-block", "aria-label": label ?? null },
    h("span", { "aria-hidden": "true" }, groups),
    h("span", { class: "visually-hidden" }, value),
    h("span", { class: "count" }, `${value.length} characters`),
  );
}
