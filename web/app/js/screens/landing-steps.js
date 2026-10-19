import { h } from "../ui/h.js";
import { svg } from "../ui/svg.js";

const titles = [
  "Proved and sealed on this device",
  "Settling on the pool, from your account",
  "Settled",
];

const icon = (state) => {
  const ring = [
    "circle",
    { cx: "11", cy: "11", r: "9", fill: "none", stroke: "currentColor", "stroke-width": "1.8" },
  ];
  if (state === "done")
    return svg(22, 22, [
      ["circle", { cx: "11", cy: "11", r: "10", fill: "currentColor" }],
      [
        "path",
        {
          d: "M6.5 11.3 9.6 14.2 15.6 8",
          fill: "none",
          stroke: "#0a0b0d",
          "stroke-width": "2",
          "stroke-linecap": "round",
          "stroke-linejoin": "round",
        },
      ],
    ]);
  if (state === "now")
    return svg(22, 22, [ring, ["circle", { cx: "11", cy: "11", r: "4.5", fill: "currentColor" }]]);
  return svg(22, 22, [ring]);
};

/**
 * Where a spend is, in the apps' list of steps, here three since the web has no lander: done steps
 * are checked, the current one filled, the rest open. A screen reader hears each step's state.
 */
export function steps(now) {
  return h(
    "ol",
    { class: "tile steps", "aria-label": "Where this spend is" },
    titles.map((title, i) => {
      const state = i < now ? "done" : i === now ? "now" : "to come";
      return h(
        "li",
        {
          class: `step${i <= now ? " reached" : ""}${i === now ? " now" : ""}`,
          "aria-label": `${title}, ${state}`,
        },
        h("span", { class: "icon" }, icon(state)),
        h("span", { "aria-hidden": "true" }, title),
      );
    }),
  );
}
