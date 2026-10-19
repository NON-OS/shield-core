import { h } from "./h.js";

/** The apps' quiet group: plain rows in one outline, each a secondary action. */
export function quiet(rows) {
  return h(
    "nav",
    { class: "quiet-group" },
    rows
      .filter(Boolean)
      .map(([label, action, disabled]) =>
        h(
          "button",
          { type: "button", class: "quiet", onclick: action, disabled: Boolean(disabled) },
          label,
        ),
      ),
  );
}
