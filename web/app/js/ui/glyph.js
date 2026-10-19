// The signs on the round actions, as the Android app draws them: strokes through points given as
// fractions of a square, a tenth of the side thick, with round caps.

import { svg } from "./svg.js";

const lines = {
  up: [
    [
      [0.5, 0.8],
      [0.5, 0.2],
    ],
    [
      [0.32, 0.38],
      [0.5, 0.2],
      [0.68, 0.38],
    ],
  ],
  down: [
    [
      [0.5, 0.2],
      [0.5, 0.8],
    ],
    [
      [0.32, 0.62],
      [0.5, 0.8],
      [0.68, 0.62],
    ],
  ],
  swap: [
    [
      [0.33, 0.8],
      [0.33, 0.2],
    ],
    [
      [0.18, 0.36],
      [0.33, 0.2],
      [0.48, 0.36],
    ],
    [
      [0.67, 0.2],
      [0.67, 0.8],
    ],
    [
      [0.52, 0.64],
      [0.67, 0.8],
      [0.82, 0.64],
    ],
  ],
  in: [
    [
      [0.5, 0.15],
      [0.5, 0.65],
    ],
    [
      [0.32, 0.48],
      [0.5, 0.65],
      [0.68, 0.48],
    ],
    [
      [0.2, 0.85],
      [0.8, 0.85],
    ],
  ],
  out: [
    [
      [0.5, 0.85],
      [0.5, 0.35],
    ],
    [
      [0.32, 0.52],
      [0.5, 0.35],
      [0.68, 0.52],
    ],
    [
      [0.2, 0.15],
      [0.8, 0.15],
    ],
  ],
  shield: [
    [
      [0.5, 0.1],
      [0.8, 0.24],
      [0.8, 0.5],
      [0.72, 0.7],
      [0.5, 0.9],
      [0.28, 0.7],
      [0.2, 0.5],
      [0.2, 0.24],
      [0.5, 0.1],
    ],
  ],
};

export function glyph(name, side = 22) {
  return svg(
    side,
    side,
    lines[name].map((points) => [
      "polyline",
      {
        points: points.map(([x, y]) => `${x * side},${y * side}`).join(" "),
        fill: "none",
        stroke: "currentColor",
        "stroke-width": String(side * 0.1),
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
      },
    ]),
  );
}
