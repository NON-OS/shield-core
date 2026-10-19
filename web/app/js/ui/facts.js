import { h } from "./h.js";

/** Label and value pairs, read by a screen reader as a description list. */
export function facts(rows) {
  return h(
    "dl",
    { class: "facts" },
    rows.filter(Boolean).flatMap(([label, value]) => [h("dt", {}, label), h("dd", {}, value)]),
  );
}
