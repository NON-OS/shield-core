import { svg } from "./svg.js";

/** The apps' Back: a chevron in a 44 point target, read out as "Back". */
export function back(action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "back";
  button.setAttribute("aria-label", "Back");
  button.addEventListener("click", action);
  button.append(
    svg(16, 16, [
      [
        "path",
        {
          d: "M10.5 2.5 5 8l5.5 5.5",
          fill: "none",
          stroke: "currentColor",
          "stroke-width": "2",
          "stroke-linecap": "round",
          "stroke-linejoin": "round",
        },
      ],
    ]),
  );
  return button;
}
