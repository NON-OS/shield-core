import { test } from "node:test";
import assert from "node:assert/strict";
import { standardBelow } from "./standard-below.js";

test("a deposit note after the pool's fee sends the size below it", () => {
  assert.equal(standardBelow("0.0199"), "0.01");
  assert.equal(standardBelow("0.00398"), "0.002");
  assert.equal(standardBelow("4,975"), "2000");
});

test("an exact standard size sends the one below it, and nothing is below the smallest unit", () => {
  assert.equal(standardBelow("0.05"), "0.02");
  assert.equal(standardBelow("1"), "0.5");
  assert.equal(standardBelow("0.000000000000000001"), null);
});
