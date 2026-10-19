// Each coin's mark, as the apps draw it: the Ethereum diamond in paper, the NØNOS Ø for NOX, and
// USDC's blue disc. The name beside it says which coin, so the mark is not read out.

import { h } from "./h.js";
import { svg } from "./svg.js";

const upper = [
  [0.5, 0.05],
  [0.79, 0.55],
  [0.5, 0.68],
  [0.21, 0.55],
];
const lower = [
  [0.21, 0.61],
  [0.5, 0.95],
  [0.79, 0.61],
  [0.5, 0.74],
];
const mark = () => new URL("../../images/mark.svg", import.meta.url).href;

export function coinLogo(coin, side = 34) {
  if (coin === "eth") {
    const shape = (pts) => [
      "polygon",
      { points: pts.map(([x, y]) => `${x * side},${y * side}`).join(" "), fill: "#f2f3f7" },
    ];
    return svg(side, side, [shape(upper), shape(lower)]);
  }
  if (coin === "nox")
    return h("img", { src: mark(), alt: "", width: side * 0.8, height: side * 0.8 * (204 / 188) });
  return h("span", { class: "usdc", "aria-hidden": "true" }, "$");
}
