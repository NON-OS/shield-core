import { h } from "./h.js";
import { svg } from "./svg.js";

const chevron = () =>
  svg(16, 16, [
    [
      "path",
      {
        d: "M6 3.5 10.5 8 6 12.5",
        fill: "none",
        stroke: "currentColor",
        "stroke-width": "1.6",
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
      },
    ],
  ]);

/**
 * The apps' quiet group: plain rows in one outline, each a secondary action. A row is
 * `[label, action, disabled]`, or `{ label, action, value, danger, disabled }` where `value` is a
 * setting's current state, shown at the right, and `danger` marks an action that destroys.
 */
export function quiet(rows) {
  return h(
    "nav",
    { class: "quiet-group" },
    rows.filter(Boolean).map((row) => {
      const r = Array.isArray(row) ? { label: row[0], action: row[1], disabled: row[2] } : row;
      return h(
        "button",
        {
          type: "button",
          class: `quiet${r.danger ? " danger" : ""}`,
          onclick: r.action,
          disabled: Boolean(r.disabled),
        },
        h("span", { class: "label-text" }, r.label),
        r.value != null && h("span", { class: "value" }, r.value),
        h("span", { class: "go", "aria-hidden": "true" }, chevron()),
      );
    }),
  );
}
