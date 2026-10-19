// Every symbol the encoder draws is read back by an independent decoder, across the versions a
// short 0x address and a long nox1 address need.

import { test } from "node:test";
import assert from "node:assert/strict";
import jsQR from "jsqr";
import { matrix } from "./matrix.js";

function decode(modules) {
  const quiet = 4;
  const scale = 3;
  const side = (modules.length + quiet * 2) * scale;
  const pixels = new Uint8ClampedArray(side * side * 4).fill(255);
  modules.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (!dark) return;
      for (let dy = 0; dy < scale; dy++)
        for (let dx = 0; dx < scale; dx++) {
          const at = (((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx) * 4;
          pixels[at] = pixels[at + 1] = pixels[at + 2] = 0;
        }
    }),
  );
  return jsQR(pixels, side, side)?.data;
}

const sample = (n) =>
  Array.from({ length: n }, (_, i) => "abcdefghijklmnopqrstuvwxyz234567"[(i * 7 + 3) % 32]).join(
    "",
  );

for (const n of [1, 17, 42, 106, 271, 500, 1000, 1500, 2005, 2900]) {
  test(`a ${n}-character string reads back`, () => {
    const text = n === 42 ? "0x9c926E3113836E6A59643d1aaC31Fd2d5e34f8b7" : sample(n);
    const modules = matrix(text);
    assert.ok(modules, "it fits");
    assert.equal(decode(modules), text);
  });
}

test("more than version 40 holds is refused", () => {
  assert.equal(matrix(sample(3000)), null);
});
